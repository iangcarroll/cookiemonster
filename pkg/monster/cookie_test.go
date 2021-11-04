package monster

import (
	"encoding/base64"
	"testing"
)

func TestNewCookie(t *testing.T) {
	c := NewCookie("abc")

	if c.raw != "abc" {
		t.Errorf("raw malformed")
	}

	if c.decodedBy == nil {
		t.Errorf("decodedBy malformed")
	}
}

func TestDecodeDjango(t *testing.T) {
	validCookie := NewCookie("gAJ9cQFVBV9uZXh0cQJYAQAAAC9zLg:1mh2IM:rAOWFyG5ROIOxriY8pwm9jFma5w")
	if !validCookie.Decode() {
		t.Errorf("cannot decode valid django cookie")
	}

	invalidCookie := NewCookie("garbage:garbage:garbage")
	if invalidCookie.Decode() {
		t.Errorf("decoded invalid cookie")
	}

	garbageCookie := NewCookie("garbagegarbagegarbagegarbagegarbagegarbagegarbage")
	if garbageCookie.Decode() {
		t.Errorf("decoded garbage")
	}
}

func TestDecodeJWT(t *testing.T) {
	validCookie := NewCookie("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.O39wphnad2iRtKulTeEmBdPLz1s22_XihMtD7swLx_o")
	if !validCookie.Decode() {
		t.Errorf("cannot decode valid jwt cookie")
	}

	wl := NewWordlist()

	if err := wl.LoadFromArray([][]byte{[]byte("changeme")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func TestDecodeEncodedJWT(t *testing.T) {
	validCookie := NewCookie(base64.StdEncoding.EncodeToString([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.O39wphnad2iRtKulTeEmBdPLz1s22_XihMtD7swLx_o")))

	if !validCookie.Decode() {
		t.Errorf("cannot decode valid jwt cookie")
	}

	wl := NewWordlist()

	if err := wl.LoadFromArray([][]byte{[]byte("changeme")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func TestDecodeRack(t *testing.T) {
	validCookie := NewCookie("BAhJIgl0ZXN0BjoGRVQ=--8c5ae09ed57f1e933cc466f5b99ea636d1fc31a2")
	if !validCookie.Decode() {
		t.Errorf("cannot decode valid rack cookie")
	}

	wl := NewWordlist()

	if err := wl.LoadFromArray([][]byte{[]byte("super secret")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func BenchmarkUnsignRack(b *testing.B) {
	wl := NewWordlist()
	if err := wl.LoadFromArray([][]byte{[]byte("super secret")}); err != nil {
		b.Error("could not LoadFromArray")
	}

	for n := 0; n < b.N; n++ {
		validCookie := NewCookie("BAhJIgl0ZXN0BjoGRVQ=--8c5ae09ed57f1e933cc466f5b99ea636d1fc31a2")

		if !validCookie.Decode() {
			b.Error("cannot decode valid rack cookie")
		}

		if _, success := validCookie.Unsign(wl, 10); !success {
			b.Error("could not unsign an unsignable cookie")
		}
	}
}

func TestDecodeExpress(t *testing.T) {
	// set-cookie: session=eyJjb3VudGVyIjoxfQ==; path=/; expires=Mon, 01 Nov 2021 09:30:14 GMT; httponly
	// set-cookie: session.sig=sBbqNOWS3EYjdkG7Che2KU9IkT4; path=/; expires=Mon, 01 Nov 2021 09:30:14 GMT; httponly
	validCookie := NewCookie("session=eyJhbmltYWxzIjoibGlvbiJ9^Vf2INocdJIqKWVfYGhXwPhQZNFI")

	if !validCookie.Decode() {
		t.Errorf("cannot decode valid express cookie")
	}

	wl := NewWordlist()
	if err := wl.LoadFromArray([][]byte{[]byte("changeme")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func TestDecodeLaravel(t *testing.T) {
	// Set-Cookie: laravel_session=eyJpdiI6IkJPV3Q1Q09OSGt3aitXbmZqdU5Fa2c9PSIsInZhbHVlIjoiVzVtWmlienduaHBWbEg2Mzh3SWFkTHFGWXVucDl3T0Z2SjA1cERQK0N1Zit5S0RyZzU3emxQTks2Q3VUWkl5RllyU3ljSGZScEpsUHhRTFgvaDVqa3lsOVY1WUZJQTJyM3gvMWRVN3BLSzVQQk12ZjJJcDhtdFo3MUR2WTdhajMiLCJtYWMiOiI3YjVmYTQ1ZjRjMjlhYTkzOTFhNWIxNjNlNjUyMzAxNDA1NWU4NDc0NGZjZGZjZGQ5NDUzMDhiYTRiZjI0NzYyIiwidGFnIjoiIn0%3D; expires=Mon, 01-Nov-2021 08:03:28 GMT; Max-Age=7200; path=/; httponly; samesite=lax
	validCookie := NewCookie("eyJpdiI6IkJPV3Q1Q09OSGt3aitXbmZqdU5Fa2c9PSIsInZhbHVlIjoiVzVtWmlienduaHBWbEg2Mzh3SWFkTHFGWXVucDl3T0Z2SjA1cERQK0N1Zit5S0RyZzU3emxQTks2Q3VUWkl5RllyU3ljSGZScEpsUHhRTFgvaDVqa3lsOVY1WUZJQTJyM3gvMWRVN3BLSzVQQk12ZjJJcDhtdFo3MUR2WTdhajMiLCJtYWMiOiI3YjVmYTQ1ZjRjMjlhYTkzOTFhNWIxNjNlNjUyMzAxNDA1NWU4NDc0NGZjZGZjZGQ5NDUzMDhiYTRiZjI0NzYyIiwidGFnIjoiIn0%3D")

	if !validCookie.Decode() {
		t.Errorf("cannot decode valid laravel cookie")
	}

	wl := NewWordlist()
	if err := wl.LoadFromArray([][]byte{[]byte("zseMzUq8M6oPB5xkPvIWddeepxzseJtN")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func TestDecodeFlask(t *testing.T) {
	validCookie := NewCookie("eyJjc3JmX3Rva2VuIjoiYjAxNDZjZGIzZGZiMTliYWM1N2EyNGU5M2U2YWVhNDdhOTNlNzVlZiJ9.YYN0SA.B5roVjMHOW3IYSrohS9FhgCFlHk")
	if !validCookie.Decode() {
		t.Errorf("cannot decode valid flask cookie")
	}

	wl := NewWordlist()
	if err := wl.LoadFromArray([][]byte{[]byte("secret_key")}); err != nil {
		t.Errorf("could not LoadFromArray")
	}

	if _, success := validCookie.Unsign(wl, 100); !success {
		t.Errorf("could not unsign an unsignable cookie")
	}
}

func BenchmarkUnsignFlask(b *testing.B) {
	wl := NewWordlist()
	if err := wl.LoadFromArray([][]byte{[]byte("secret_key"), []byte("not a secret key"), []byte("not the secret key")}); err != nil {
		b.Error("could not LoadFromArray")
	}

	for n := 0; n < b.N; n++ {
		validCookie := NewCookie("eyJjc3JmX3Rva2VuIjoiYjAxNDZjZGIzZGZiMTliYWM1N2EyNGU5M2U2YWVhNDdhOTNlNzVlZiJ9.YYN0SA.B5roVjMHOW3IYSrohS9FhgCFlHk")

		if !validCookie.Decode() {
			b.Error("cannot decode valid flask cookie")
		}

		if _, success := validCookie.Unsign(wl, 100); !success {
			b.Error("could not unsign an unsignable cookie")
		}
	}
}
