package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type itsdangerousParsedData struct {
	data             string
	signature        string
	decodedSignature []byte
	timestamp        string
	decodedTimestamp []byte
	algorithm        string
	toBeSigned       []byte

	compressed bool
	parsed     bool
}

func (d *itsdangerousParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Compressed: %t\nData: %s\nSignature: %s\nAlgorithm: %s\n", d.compressed, d.data, d.signature, d.algorithm)
}

const (
	itsdangerousDecoder   = "itsdangerous"
	itsdangerousMinLength = 10

	itsdangerousSeparator = `.`
)

var (
	itsdangerousAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
		48: "sha384",
		64: "sha512",
	}

	itsdangerousSalt = "itsdangerous"
)

func itsdangerousDecode(c *Cookie) bool {
	if len(c.raw) < itsdangerousMinLength {
		return false
	}

	rawData := c.raw
	var parsedData itsdangerousParsedData

	// If the first character is a dot, it's compressed.
	if rawData[0] == '.' {
		parsedData.compressed = true
		rawData = rawData[1:]
	}

	// Break the cookie out into the session data and signature.
	components := strings.Split(rawData, itsdangerousSeparator)
	if len(components) != 2 && len(components) != 3 {
		return false
	}

	if len(components) == 2 {
		parsedData.data = components[0]
		parsedData.signature = components[1]
	} else {
		parsedData.data = components[0]
		parsedData.timestamp = components[1]
		parsedData.signature = components[2]
	}

	// itsdangerous encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedTimestamp, err := base64.RawURLEncoding.DecodeString(parsedData.timestamp)
	if err != nil {
		return false
	}

	if len(decodedTimestamp) > 8 {
		return false
	}

	parsedData.decodedTimestamp = decodedTimestamp

	// itsdangerous encodes the signature with URL-safe base64
	// without padding, so we must use `RawURLEncoding`.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	// Determine the algorithm from the digest length, or give up if we can't
	// figure it out.
	if alg, ok := itsdangerousAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature

	if len(parsedData.decodedTimestamp) > 0 {
		parsedData.toBeSigned = []byte(parsedData.data + itsdangerousSeparator + parsedData.timestamp)
	} else {
		parsedData.toBeSigned = []byte(parsedData.data)
	}

	// If this is a compressed cookie, it needs to have the dot in front which
	// we previously stripped from `data`.
	if parsedData.compressed {
		parsedData.toBeSigned = append([]byte("."), parsedData.toBeSigned...)
	}

	parsedData.parsed = true
	c.wasDecodedBy(itsdangerousDecoder, &parsedData)
	return true
}

func itsdangerousUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(itsdangerousDecoder).(*itsdangerousParsedData)

	// Derive the correct signature, if this was the correct secret key.
	computedSignature := itsdangerousCompute(parsedData.algorithm, secret, parsedData.toBeSigned)

	// Compare this signature to the one in the `Cookie`.
	return bytes.Equal(parsedData.decodedSignature, computedSignature)
}

func itsdangerousCompute(algorithm string, secret []byte, data []byte) []byte {
	switch algorithm {
	case "sha1":
		// Itsdangerous forces us to derive a key for HMAC-ing.
		derivedKey := sha1Digest(itsdangerousSalt + "signer" + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha1HMAC(derivedKey, data)
	case "sha256":
		// Itsdangerous forces us to derive a key for HMAC-ing.
		derivedKey := sha256Digest(itsdangerousSalt + "signer" + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha256HMAC(derivedKey, data)
	case "sha384":
		// Itsdangerous forces us to derive a key for HMAC-ing.
		derivedKey := sha384Digest(itsdangerousSalt + "signer" + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha384HMAC(derivedKey, data)
	case "sha512":
		// Itsdangerous forces us to derive a key for HMAC-ing.
		derivedKey := sha512Digest(itsdangerousSalt + "signer" + string(secret))

		// Derive the correct signature, if this was the correct secret key.
		return sha512HMAC(derivedKey, data)
	default:
		panic("unknown algorithm")
	}
}
