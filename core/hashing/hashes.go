package hashing

import (
	"encoding/binary"
)

const (
	// offset64 FNVa offset
	offset64 = 14695981039346656037
	// prime64 FNVa prime value.
	prime64 = 1099511628211
)

//fnva hash function
func Sum64(key string) []byte {
	var hash uint64 = offset64
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= prime64
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, hash)
	return b
}
