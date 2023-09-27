package testutils

import (
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"testing"
)

type LogObserver struct {
	Logger *zap.Logger
	Logs   *observer.ObservedLogs
}

func (o LogObserver) AssertLogSize(t *testing.T, i int) {
	assert.Equal(t, i, o.Logs.Len())
}

func (o LogObserver) AssertMessageEqual(t *testing.T, messageId int, message string) {
	if o.Logs.Len()-1 < messageId {
		t.Fatalf("messageid too low")
	}
	assert.Equal(t, message, o.Logs.All()[messageId].Message)
}

func CreateAllLevelLogObserver() LogObserver {
	zapCore, logs := observer.New(zap.DebugLevel)
	observedLogger := zap.New(zapCore)
	return LogObserver{Logger: observedLogger, Logs: logs}

}
