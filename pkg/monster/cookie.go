package monster

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
)

// Returns a new `Cookie`, which must then be used with
// `Decode()` and then `Unsign()`.
func NewCookie(raw string) *Cookie {
	return &Cookie{raw: raw, decodedBy: make(map[string]interface{})}
}

// Decodes a `Cookie` into its components, trying all of the
// available decoders. Decode is not thread-safe.
func (c *Cookie) Decode() (success bool) {
	if djangoDecode(c) {
		success = true
	}

	if flaskDecode(c) {
		success = true
	}

	if jwtDecode(c) {
		success = true
	}

	if rackDecode(c) {
		success = true
	}

	if expressDecode(c) {
		success = true
	}

	if laravelDecode(c) {
		success = true
	}

	if !success && c.unwrap() {
		return c.Decode()
	}

	return success
}

// Uses the decoded data from `Decode()` to attempt to unsign the cookie
// with a given wordlist. Unsign is not thread-safe.
func (c *Cookie) Unsign(wl *Wordlist, concurrencyLimit uint64) (key []byte, success bool) {
	shouldUseDjango := c.hasParsedDataFor(djangoDecoder)
	shouldUseFlask := c.hasParsedDataFor(flaskDecoder)
	shouldUseJwt := c.hasParsedDataFor(jwtDecoder)
	shouldUseRack := c.hasParsedDataFor(rackDecoder)
	shouldUseExpress := c.hasParsedDataFor(expressDecoder)
	shouldUseLaravel := c.hasParsedDataFor(laravelDecoder)

	// This looks a bit silly right now, but as we add more decoders, this
	// should be here to ensure we don't do pointless work.
	if !shouldUseDjango && !shouldUseFlask && !shouldUseJwt && !shouldUseRack && !shouldUseExpress && !shouldUseLaravel {
		return nil, false
	}

	var wg sync.WaitGroup

	// We use a limiter (abusing channels) to throttle the amount of
	// goroutines we run at a time.
	limiter := newLimiter(concurrencyLimit)

	for _, entry := range wl.Entries() {
		wg.Add(1)
		limiter.Add()

		go func(entry []byte) {
			defer wg.Done()
			defer limiter.Done()

			if shouldUseDjango && djangoUnsign(c, entry) {
				c.wasUnsignedBy(djangoDecoder, entry)
			}

			if shouldUseFlask && flaskUnsign(c, entry) {
				c.wasUnsignedBy(flaskDecoder, entry)
			}

			if shouldUseJwt && jwtUnsign(c, entry) {
				c.wasUnsignedBy(jwtDecoder, entry)
			}

			if shouldUseRack && rackUnsign(c, entry) {
				c.wasUnsignedBy(rackDecoder, entry)
			}

			if shouldUseExpress && expressUnsign(c, entry) {
				c.wasUnsignedBy(expressDecoder, entry)
			}

			if shouldUseLaravel && laravelUnsign(c, entry) {
				c.wasUnsignedBy(laravelDecoder, entry)
			}
		}(entry)
	}

	wg.Wait()
	return c.unsignedKey, c.wasUnsigned()
}

func (c *Cookie) Resign(data string) string {
	c.unsignedMutex.RLock()
	defer c.unsignedMutex.RUnlock()

	if len(c.unsignedBy) == 0 {
		panic("cannot resign a cookie that was not unsigned")
	}

	switch c.unsignedBy {
	case djangoDecoder:
		return djangoResign(c, data, c.unsignedKey)
	default:
		return ""
	}
}

// Returns debug information from decoders.
func (c *Cookie) String() (out string) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	out += "\n"

	if val, ok := c.decodedBy[djangoDecoder]; ok {
		out += "Decoder django reports:\n" + val.(*djangoParsedData).String() + "\n"
	}

	if val, ok := c.decodedBy[flaskDecoder]; ok {
		out += "Decoder flask reports:\n" + val.(*flaskParsedData).String() + "\n"
	}

	if val, ok := c.decodedBy[jwtDecoder]; ok {
		out += "Decoder jwt reports:\n" + val.(*jwtParsedData).String() + "\n"
	}

	if val, ok := c.decodedBy[rackDecoder]; ok {
		out += "Decoder rack reports:\n" + val.(*rackParsedData).String() + "\n"
	}

	if val, ok := c.decodedBy[expressDecoder]; ok {
		out += "Decoder express reports:\n" + val.(*expressParsedData).String() + "\n"
	}

	if val, ok := c.decodedBy[laravelDecoder]; ok {
		out += "Decoder laravel reports:\n" + val.(*laravelParsedData).String() + "\n"
	}

	return out
}

// Returns the key and decoder if the cookie was decoded.
func (c *Cookie) Result() (success bool, key []byte, decoder string) {
	c.unsignedMutex.RLock()
	defer c.unsignedMutex.RUnlock()

	if len(c.unsignedBy) == 0 {
		return false, nil, ""
	}

	return true, c.unsignedKey, c.unsignedBy
}

func (c *Cookie) wasDecodedBy(decoder string, data interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.decodedBy[decoder] = data
}

func (c *Cookie) wasUnsignedBy(decoder string, key []byte) {
	c.unsignedMutex.Lock()
	defer c.unsignedMutex.Unlock()

	if len(c.unsignedBy) > 0 {
		fmt.Println("Unusual circumstance of a Cookie being unsigned multiple times")
	}

	c.unsignedBy = decoder
	c.unsignedKey = key
}

func (c *Cookie) wasUnsigned() bool {
	c.unsignedMutex.RLock()
	defer c.unsignedMutex.RUnlock()

	return len(c.unsignedBy) > 0
}

func (c *Cookie) parsedDataFor(decoder string) interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if val, ok := c.decodedBy[decoder]; ok {
		return val
	}

	panic("We needed parsed data for " + decoder + " but did not have it.")
}

func (c *Cookie) hasParsedDataFor(decoder string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exists := c.decodedBy[decoder]
	return exists
}

// If we couldn't initially decode this cookie, try unwrapping it from
// URL-encoding and base64-encoding. This is not thread-safe.
func (c *Cookie) unwrap() (success bool) {
	// Only do this once.
	if c.wasUnwrapped {
		return false
	}

	out := c.raw

	urlDecode, err := url.QueryUnescape(out)
	if urlDecode != out && err == nil {
		success = true
		out = urlDecode
	}

	base64Decode, err := base64.StdEncoding.DecodeString(out)
	if string(base64Decode) != out && err == nil {
		success = true
		out = string(base64Decode)
	}

	c.wasUnwrapped = true
	c.raw = out
	return success
}
