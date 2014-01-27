package md5

import (
	"hash"
)

// The blocksize of MD5 in bytes.
const BlockSize = 64

// The size of an MD5 checksum in bytes.
const Size = 16

// New returns a new hash.Hash computing the MD5 checksum.
func New() hash.Hash {
	return &hash.Hash
}

// Sum returns the MD5 checksum of the data.
func Sum(data []byte) [Size]byte {
}
