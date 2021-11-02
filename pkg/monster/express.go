package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type expressParsedData struct {
	data             string
	signature        string
	decodedSignature []byte
	algorithm        string

	parsed bool
}

func (d *expressParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Data: %s\nSignature: %s\nAlgorithm: %s\n", d.data, d.signature, d.algorithm)
}

const (
	expressDecoder   = "express"
	expressMinLength = 10

	// Express (or cookie-session, rather) sends the signature in another
	// cookie, which is rather annoying. We use a distinct separator and
	// ask users to manually assemble this.
	expressSeparator = `^`
)

var (
	expressAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}
)

func expressDecode(c *Cookie) bool {
	if len(c.raw) < expressMinLength {
		return false
	}

	rawData := c.raw
	var parsedData expressParsedData

	// Break the cookie out into the session data and signature.
	components := strings.Split(rawData, expressSeparator)
	if len(components) != 2 {
		return false
	}

	parsedData.data = components[0]
	parsedData.signature = components[1]

	// Express encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := expressAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.parsed = true
	c.wasDecodedBy(expressDecoder, &parsedData)

	return true
}

func expressUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(expressDecoder).(*expressParsedData)
	toBeSigned := parsedData.data

	switch parsedData.algorithm {
	case "sha1":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha1HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha256":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha256HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha384":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha384HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha512":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha512HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	default:
		panic("unknown algorithm")
	}
}
