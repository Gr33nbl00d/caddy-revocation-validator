package crlstore

import "fmt"

type StoreType int32

const (
	Map     StoreType = 0
	LevelDB StoreType = 1
)

func StoreTypeToString(storeType StoreType) string {
	switch storeType {
	case LevelDB:
		return "Level DB"
	case Map:
		return "Map"
	default:
		return fmt.Sprintf("unknown store type %d", storeType)
	}
}
