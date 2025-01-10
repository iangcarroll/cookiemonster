package monster

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

type codeigniterParsedData struct {
	body             string
	signature        string
	decodedSignature []byte
	algorithm        string

	parsed bool
}

func (d *codeigniterParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Header: %s\nBody: %s\n", d.body, d.signature)
}

const (
	codeigniterDecoder   = "codeigniter"
	codeigniterMinLength = 100

	codeigniterAlgoithmSha1 = "sha1"
	codeigniterAlgoithmMd5  = "md5"
)

func codeigniterDecode(c *Cookie) bool {
	if len(c.raw) < codeigniterMinLength {
		return false
	}

	rawData := c.raw
	// If the cookie doesn't contain the expected fields, it's not a CodeIgniter cookie.
	if !strings.Contains(rawData, "session_id") || !strings.Contains(rawData, "user_agent") {
		return false
	}

	var parsedData codeigniterParsedData

	// The last 32 or 40 characters are the hex-encoded MD5 or SHA1 signature.
	hashComponent := rawData[len(rawData)-40:]
	parsedData.body = rawData[:len(rawData)-40]
	parsedData.signature = hashComponent
	parsedData.algorithm = codeigniterAlgoithmSha1

	decodedSignature, err := hex.DecodeString(hashComponent)

	// If we failed to decode the signature, it could be using MD5.
	if err != nil {
		hashComponent = rawData[len(rawData)-32:]
		parsedData.body = rawData[:len(rawData)-32]
		parsedData.signature = hashComponent
		parsedData.algorithm = codeigniterAlgoithmMd5

		decodedSignature, err = hex.DecodeString(hashComponent)
		if err != nil {
			return false
		}
	}

	urlDecodedBody, err := url.QueryUnescape(parsedData.body)
	if err == nil {
		parsedData.body = urlDecodedBody
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.parsed = true

	c.wasDecodedBy(codeigniterDecoder, &parsedData)
	return true
}

func codeigniterUnsign(c *Cookie, secret []byte) bool {
	// We need to extract `toBeSigned` to prepare what we'll be signing.
	parsedData := c.parsedDataFor(codeigniterDecoder).(*codeigniterParsedData)

	switch parsedData.algorithm {
	case codeigniterAlgoithmMd5:
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := md5Digest(parsedData.body + string(secret))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	case codeigniterAlgoithmSha1:
		// Derive the correct signature, if this was the correct secret key.
		computedSignature := sha1Digest(parsedData.body + string(secret))

		// Compare this signature to the one in the `Cookie`.
		return bytes.Equal(parsedData.decodedSignature, computedSignature)
	default:
		panic("Unknown algorithm")
	}
}
