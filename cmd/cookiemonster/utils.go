package main

import (
	"encoding/base64"
	"unicode"
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func base64Key(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}
