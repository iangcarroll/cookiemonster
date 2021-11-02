package monster

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

type rackParsedData struct {
	data             string
	signature        string
	decodedSignature []byte
	algorithm        string

	parsed bool
}

func (d *rackParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Data: %s\nSignature: %s\nAlgorithm: %s\n", d.data, d.signature, d.algorithm)
}

const (
	rackDecoder   = "rack"
	rackMinLength = 10

	rackSeparator = `--`
)

var (
	rackAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}
)

func rackDecode(c *Cookie) bool {
	if len(c.raw) < rackMinLength {
		return false
	}

	rawData := c.raw
	var parsedData rackParsedData

	// Break the cookie out into the session data and signature.
	components := strings.Split(rawData, rackSeparator)
	if len(components) != 2 {
		return false
	}

	parsedData.data = components[0]
	parsedData.signature = components[1]

	// Flask encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := hex.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := rackAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.parsed = true
	c.wasDecodedBy(rackDecoder, &parsedData)

	return true
}

func rackUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(rackDecoder).(*rackParsedData)
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
