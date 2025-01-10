package monster

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

func md5Digest(data string) []byte {
	h := md5.New()

	if writtenLength, err := h.Write([]byte(data)); err != nil || writtenLength != len(data) {
		panic("md5Digest could not properly write data")
	}

	return h.Sum(nil)
}

func sha1Digest(data string) []byte {
	h := sha1.New()

	if writtenLength, err := h.Write([]byte(data)); err != nil || writtenLength != len(data) {
		panic("sha1Digest could not properly write data")
	}

	return h.Sum(nil)
}

func sha1HMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha1.New, []byte(key))

	if writtenLength, err := h.Write(data); err != nil || writtenLength != len(data) {
		panic("sha1HMAC could not properly write data")
	}

	return h.Sum(nil)
}

func sha256Digest(data string) []byte {
	h := sha256.New()

	if writtenLength, err := h.Write([]byte(data)); err != nil || writtenLength != len(data) {
		panic("sha256Digest could not properly write data")
	}

	return h.Sum(nil)
}

func sha256HMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))

	if writtenLength, err := h.Write(data); err != nil || writtenLength != len(data) {
		panic("sha256HMAC could not properly write data")
	}

	return h.Sum(nil)
}

func sha384Digest(data string) []byte {
	h := sha512.New384()

	if writtenLength, err := h.Write([]byte(data)); err != nil || writtenLength != len(data) {
		panic("sha384Digest could not properly write data")
	}

	return h.Sum(nil)
}

func sha384HMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha512.New384, []byte(key))

	if writtenLength, err := h.Write(data); err != nil || writtenLength != len(data) {
		panic("sha384HMAC could not properly write data")
	}

	return h.Sum(nil)
}

func sha512Digest(data string) []byte {
	h := sha512.New()

	if writtenLength, err := h.Write([]byte(data)); err != nil || writtenLength != len(data) {
		panic("sha512Digest could not properly write data")
	}

	return h.Sum(nil)
}

func sha512HMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha512.New, []byte(key))

	if writtenLength, err := h.Write(data); err != nil || writtenLength != len(data) {
		panic("sha512HMAC could not properly write data")
	}

	return h.Sum(nil)
}
