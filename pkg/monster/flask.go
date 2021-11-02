package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type flaskParsedData struct {
	data             string
	timestamp        string
	signature        string
	decodedSignature []byte
	algorithm        string

	compressed bool
	parsed     bool
}

func (d *flaskParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Compressed: %t\nData: %s\nTimestamp: %s\nSignature: %s\nAlgorithm: %s\n", d.compressed, d.data, d.timestamp, d.signature, d.algorithm)
}

const (
	flaskDecoder   = "flask"
	flaskMinLength = 10

	flaskSeparator = `.`
	flaskSalt      = `cookie-session`
)

var (
	flaskAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}
)

func flaskDecode(c *Cookie) bool {
	if len(c.raw) < flaskMinLength {
		return false
	}

	rawData := c.raw
	var parsedData flaskParsedData

	// If the first character is a dot, it's compressed.
	if rawData[0] == '.' {
		parsedData.compressed = true
		rawData = rawData[1:]
	}

	// Break the cookie out into the session data, timestamp, and signature,
	// in that order. Note that we assume the use of `TimestampSigner`.
	components := strings.Split(rawData, flaskSeparator)
	if len(components) != 3 {
		return false
	}

	parsedData.data = components[0]
	parsedData.timestamp = components[1]
	parsedData.signature = components[2]

	// Flask encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := flaskAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.parsed = true
	c.wasDecodedBy(flaskDecoder, &parsedData)

	return true
}

func flaskUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(flaskDecoder).(*flaskParsedData)
	toBeSigned := parsedData.data + flaskSeparator + parsedData.timestamp

	switch parsedData.algorithm {
	case "sha1":
		// Flask forces us to derive a key for HMAC-ing.
		derivedKey := sha1HMAC(secret, []byte(flaskSalt))

		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha1HMAC(derivedKey, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha256":
		// Flask forces us to derive a key for HMAC-ing.
		derivedKey := sha256HMAC(secret, []byte(flaskSalt))

		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha256HMAC(derivedKey, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha384":
		// Flask forces us to derive a key for HMAC-ing.
		derivedKey := sha384HMAC(secret, []byte(flaskSalt))

		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha384HMAC(derivedKey, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	case "sha512":
		// Flask forces us to derive a key for HMAC-ing.
		derivedKey := sha512HMAC(secret, []byte(flaskSalt))

		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha512HMAC(derivedKey, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0
	default:
		panic("unknown algorithm")
	}
}
