package crlloader

import (
	"fmt"
	"go.uber.org/zap"
	"strings"
)

type MultiSchemesCRLLoader struct {
	Loaders              []CRLLoader
	Logger               *zap.Logger
	lastSuccessfulLoader CRLLoader
}

func (f MultiSchemesCRLLoader) LoadCRL(filePath string) error {
	if f.lastSuccessfulLoader != nil {
		err := f.lastSuccessfulLoader.LoadCRL(filePath)
		if err != nil {
			return nil
		} else {
			f.Logger.Warn("failed to load CRL from loader", zap.String("loader", f.lastSuccessfulLoader.GetDescription()))
		}
	}
	for _, loader := range f.Loaders {
		if loader == f.lastSuccessfulLoader {
			continue
		}
		err := loader.LoadCRL(filePath)
		if err != nil {
			f.Logger.Warn("failed to load CRL from loader", zap.String("loader", loader.GetDescription()))
		} else {
			f.lastSuccessfulLoader = loader
			return nil
		}
	}
	return fmt.Errorf("failed to load CRL from all loaders %+v", f.Loaders)
}

func (f MultiSchemesCRLLoader) GetCRLLocationIdentifier() (string, error) {
	builder := strings.Builder{}
	for _, loader := range f.Loaders {
		identifier, err := loader.GetCRLLocationIdentifier()
		if err != nil {
			return "", err
		}
		builder.WriteString(identifier)
	}
	return calculateHashHexString(builder.String()), nil
}

func (f MultiSchemesCRLLoader) GetDescription() string {
	builder := strings.Builder{}
	for _, loader := range f.Loaders {
		description := loader.GetDescription()
		builder.WriteString(description)
		builder.WriteString(", ")
	}
	return builder.String()
}
