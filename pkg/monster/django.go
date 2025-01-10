package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type djangoParsedData struct {
	data             string
	timestamp        string
	signature        string
	decodedSignature []byte
	algorithm        string
	toBeSigned       []byte

	compressed bool
	parsed     bool
}

func (d *djangoParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Compressed: %t\nData: %s\nTimestamp: %s\nSignature: %s\nAlgorithm: %s\n", d.compressed, d.data, d.timestamp, d.signature, d.algorithm)
}

const (
	djangoDecoder   = "django"
	djangoMinLength = 10

	djangoSeparator = `:`
	djangoSalt      = `django.contrib.sessions.backends.signed_cookiessigner`
)

var (
	djangoAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}
)

func djangoDecode(c *Cookie) bool {
	if len(c.raw) < djangoMinLength {
		return false
	}

	rawData := c.raw
	var parsedData djangoParsedData

	// If the first character is a dot, it's compressed.
	if rawData[0] == '.' {
		parsedData.compressed = true
		rawData = rawData[1:]
	}

	// Break the cookie out into the session data, timestamp, and signature,
	// in that order. Note that we assume the use of `TimestampSigner`.
	components := strings.Split(rawData, djangoSeparator)
	if len(components) != 3 {
		return false
	}

	parsedData.data = components[0]
	parsedData.timestamp = components[1]
	parsedData.signature = components[2]

	// Django encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := djangoAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature

	// If compressed, we need to add back on the '.'
	toBeSignedPrefix := ""
	if parsedData.compressed {
		toBeSignedPrefix = "."
	}
	parsedData.toBeSigned = []byte(toBeSignedPrefix + parsedData.data + djangoSeparator + parsedData.timestamp)
	parsedData.parsed = true
	c.wasDecodedBy(djangoDecoder, &parsedData)
	return true
}

func djangoUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(djangoDecoder).(*djangoParsedData)

	// Derive the correct signature, if this was the correct secret key.
	computedSignature := djangoCompute(parsedData.algorithm, secret, parsedData.toBeSigned)

	// Compare this signature to the one in the `Cookie`.
	return bytes.Equal(parsedData.decodedSignature, computedSignature)
}

func djangoResign(c *Cookie, data string, secret []byte) string {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(djangoDecoder).(*djangoParsedData)

	// We need to assemble the TBS string with new data.
	toBeSigned := base64.RawURLEncoding.EncodeToString([]byte(data)) + djangoSeparator + parsedData.timestamp

	// Derive the correct signature, if this was the correct secret key.
	computedSignature := djangoCompute(parsedData.algorithm, secret, []byte(toBeSigned))
	return toBeSigned + djangoSeparator + base64.RawURLEncoding.EncodeToString(computedSignature)
}

func djangoCompute(algorithm string, secret []byte, data []byte) []byte {
	switch algorithm {
	case "sha1":
		// Django forces us to derive a key for HMAC-ing.
		derivedKey := sha1Digest(djangoSalt + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha1HMAC(derivedKey, data)
	case "sha256":
		// Django forces us to derive a key for HMAC-ing.
		derivedKey := sha256Digest(djangoSalt + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha256HMAC(derivedKey, data)
	case "sha384":
		// Django forces us to derive a key for HMAC-ing.
		derivedKey := sha384Digest(djangoSalt + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha384HMAC(derivedKey, data)
	case "sha512":
		// Django forces us to derive a key for HMAC-ing.
		derivedKey := sha512Digest(djangoSalt + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha512HMAC(derivedKey, data)
	default:
		panic("unknown algorithm")
	}
}
