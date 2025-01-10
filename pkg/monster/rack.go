package monster

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/xdg-go/pbkdf2"
)

type rackParsedData struct {
	data             string
	decodedData      []byte
	iv               string
	decodedIv        []byte
	signature        string
	decodedSignature []byte
	algorithm        string

	parsed bool
}

func (d *rackParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	if d.iv != "" {
		return fmt.Sprintf("Data: %s\nIV: %s\nSignature: %s\n Algorithm: %s\n", d.data, d.iv, d.signature, d.algorithm)
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

	// Break the cookie out into the session data and signature.
	components := strings.Split(rawData, rackSeparator)
	if len(components) == 2 {
		return rackDecodeSig(c, components)
	}
	if len(components) == 3 {
		// In Rails 5.2+, encrypted is the default
		return rackDecodeAead(c, components)
	}
	return false
}

func rackDecodeAead(c *Cookie, components []string) bool {
	var parsedData rackParsedData

	parsedData.data = components[0]
	parsedData.iv = components[1]
	parsedData.signature = components[2]

	// In the AEAD mode, the two IV and auth tag (= signature) are
	// base64 encoded and URL encoded
	unescapedIv, err := url.QueryUnescape(parsedData.iv)
	if err != nil {
		return false
	}
	rawIv, err := base64.StdEncoding.DecodeString(unescapedIv)
	if err != nil {
		return false
	}
	parsedData.decodedIv = rawIv

	unescapedSignature, err := url.QueryUnescape(parsedData.signature)
	if err != nil {
		return false
	}
	rawSignature, err := base64.StdEncoding.DecodeString(unescapedSignature)
	if err != nil {
		return false
	}
	parsedData.decodedSignature = rawSignature

	unescapedData, err := url.QueryUnescape(parsedData.data)
	if err != nil {
		return false
	}
	rawData, err := base64.StdEncoding.DecodeString(unescapedData)
	if err != nil {
		return false
	}
	parsedData.decodedData = rawData

	parsedData.algorithm = "aes-256-gcm"
	c.wasDecodedBy(rackDecoder, &parsedData)
	return true

}

func rackDecodeSig(c *Cookie, components []string) bool {
	var parsedData rackParsedData

	parsedData.data = components[0]
	parsedData.signature = components[1]

	// Rack encodes the signature with URL-safe base64
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
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	case "sha256":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha256HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	case "sha384":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha384HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	case "sha512":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha512HMAC(secret, []byte(toBeSigned))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	case "aes-256-gcm":
		// Rails 6 AES-GCM
		aesSecret := pbkdf2.Key(secret, []byte("authenticated encrypted cookie"), 1000, 32, sha256.New)
		block, err := aes.NewCipher(aesSecret)
		if err != nil {
			return false
		}
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return false
		}

		// In go, the auth tag is appended to the data
		ciphertext := append(parsedData.decodedData, parsedData.decodedSignature...)

		plaintext, err := aesGCM.Open(nil, parsedData.decodedIv, ciphertext, nil)
		if err != nil {
			return false
		}
		return json.Valid(plaintext)
	default:
		panic("unknown algorithm")
	}
}
