package crlreader

type CRLReader interface {
	ReadCRL(crlProcessor CRLProcessor, crlFilePath string) (*CRLReadResult, error)
}
