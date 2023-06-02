package monster

import (
	"encoding/base64"
	"testing"
)

func TestNewWordlist(t *testing.T) {
	wl := NewWordlist()

	tv1 := base64.StdEncoding.EncodeToString([]byte("abc"))
	tv2 := base64.StdEncoding.EncodeToString([]byte("ghi"))

	if err := wl.LoadFromString(tv1 + "\n" + tv2 + "\n"); err != nil {
		t.Error("could not load valid wordlist")
	}

	if len(wl.entries) != 2 {
		t.Error("all entries did not get loaded", len(wl.entries))
	}

	wl.LoadFromArray([][]byte{[]byte("abc")})

	if len(wl.entries) != 3 {
		t.Error("new entries did not get loaded", len(wl.entries))
	}

	if err := wl.LoadDefault(); err != nil {
		t.Error("could not load default wordlist")
	}

	if len(wl.entries) < 35000 {
		t.Error("default entries did not get loaded", len(wl.entries))
	}
}
