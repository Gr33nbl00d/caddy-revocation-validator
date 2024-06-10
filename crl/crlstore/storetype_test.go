package crlstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreTypeToString(t *testing.T) {
	tests := []struct {
		storeType StoreType
		expected  string
	}{
		{LevelDB, "Level DB"},
		{Map, "Map"},
		{StoreType(2), "unknown store type 2"},
		{StoreType(-1), "unknown store type -1"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := StoreTypeToString(test.storeType)
			assert.Equal(t, test.expected, result)
		})
	}
}
