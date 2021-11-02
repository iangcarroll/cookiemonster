package monster

import "sync"

type Cookie struct {
	raw           string
	decodedBy     map[string]interface{}
	mutex         sync.RWMutex
	unsignedBy    string
	unsignedKey   []byte
	unsignedMutex sync.RWMutex
	wasUnwrapped  bool
}

type Wordlist struct {
	loaded  bool
	path    string
	entries [][]byte
	mutex   sync.RWMutex
}
