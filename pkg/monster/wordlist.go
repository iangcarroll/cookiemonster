package monster

import (
	"bufio"
	_ "embed"
	"encoding/base64"
	"os"
	"strings"
)

//go:embed wordlists/flask-unsign.txt
var defaultWordlist string

func NewWordlist() *Wordlist {
	return &Wordlist{entries: [][]byte{}}
}

// Load wordlist entries from the provided `path`.
func (w *Wordlist) Load(path string) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		entry, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			return err
		}

		if len(entry) > 0 {
			w.entries = append(w.entries, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	w.loaded = true
	return nil
}

// Load default wordlist entries
func (w *Wordlist) LoadDefault() error {
	return w.LoadFromString(defaultWordlist)
}

// Load wordlist entries from the provided `path`.
func (w *Wordlist) LoadFromString(entries string) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	for _, line := range strings.Split(entries, "\n") {
		line = strings.TrimSpace(line)
		entry, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			return err
		}

		if len(entry) > 0 {
			w.entries = append(w.entries, entry)
		}
	}

	w.loaded = true
	return nil
}

// Load wordlist entries from the provided array of byte arrays.
func (w *Wordlist) LoadFromArray(arr [][]byte) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.entries = append(w.entries, arr...)
	w.loaded = true
	return nil
}

// Load wordlist entries from the provided array of byte arrays.
func (w *Wordlist) Count() uint64 {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	if !w.loaded {
		return 0
	}

	return uint64(len(w.entries))
}

// Load wordlist entries from the provided array of byte arrays.
func (w *Wordlist) Entries() [][]byte {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	if !w.loaded {
		panic("cannot get entries from unloaded wordlist")
	}

	return w.entries
}
