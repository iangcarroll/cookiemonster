package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type jwtParsedData struct {
	header           string
	body             string
	signature        string
	decodedSignature []byte
	algorithm        string
	toBeSigned       []byte

	parsed bool
}

func (d *jwtParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Header: %s\nBody: %s\nSignature: %s\nAlgorithm: %s\n", d.header, d.body, d.signature, d.algorithm)
}

const (
	jwtDecoder   = "jwt"
	jwtMinLength = 10

	jwtSeparator = `.`
)

var (
	jwtAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}
)

func jwtDecode(c *Cookie) bool {
	if len(c.raw) < jwtMinLength {
		return false
	}

	rawData := c.raw
	var parsedData jwtParsedData

	// Break the cookie out into the session data, timestamp, and signature,
	// in that order. Note that we assume the use of `TimestampSigner`.
	components := strings.Split(rawData, jwtSeparator)
	if len(components) != 3 {
		return false
	}

	parsedData.header = components[0]
	parsedData.body = components[1]
	parsedData.signature = components[2]

	// JWTs encode the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := jwtAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.toBeSigned = []byte(parsedData.header + jwtSeparator + parsedData.body)
	parsedData.parsed = true

	c.wasDecodedBy(jwtDecoder, &parsedData)
	return true
}

func jwtUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(jwtDecoder).(*jwtParsedData)

	switch parsedData.algorithm {
	case "sha1":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha1HMAC(secret, parsedData.toBeSigned)

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha256":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha256HMAC(secret, parsedData.toBeSigned)

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha384":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha384HMAC(secret, parsedData.toBeSigned)

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha512":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha512HMAC(secret, parsedData.toBeSigned)

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	default:
		panic("unknown algorithm")
	}
}
