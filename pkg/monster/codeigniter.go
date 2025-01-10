package monster

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
)

type codeigniterParsedData struct {
	body             string
	signature        string
	decodedSignature []byte

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
)

func codeigniterDecode(c *Cookie) bool {
	if len(c.raw) < codeigniterMinLength {
		return false
	}

	rawData := c.raw

	var parsedData codeigniterParsedData

	// The last 32 characters are the hex-encoded MD5 signature.
	hashComponent := rawData[len(rawData)-32:]
	parsedData.body = rawData[:len(rawData)-32]
	parsedData.signature = hashComponent

	decodedSignature, err := hex.DecodeString(hashComponent)
	if err != nil {
		return false
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

	// Derive the correct signature, if this was the correct secret key.
	computedSignature := md5Digest(parsedData.body + string(secret))

	// Compare this signature to the one in the `Cookie`.
	return bytes.Equal(parsedData.decodedSignature, computedSignature)
}
