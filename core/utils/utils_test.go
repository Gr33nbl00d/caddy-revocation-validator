package utils

import (
	"errors"
	"fmt"
	"github.com/smallstep/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"log"
	"strings"
	"testing"
	"time"
)

type MockRetry struct {
	countBeforeSuccess int8
}

// Mock function that returns an error.
func (p *MockRetry) mockFunction() error {
	p.countBeforeSuccess--
	if p.countBeforeSuccess == 0 {
		return nil
	} else {
		return errors.New("mock error")
	}
}

func TestRetryFailing(t *testing.T) {
	// Initialize test variables.
	retryMessageCount := 0
	attempts := 3
	expectedErr := errors.New("mock error")
	sleepTime := 20 * time.Millisecond
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(e zapcore.Entry) error {
		if e.Message == "retrying after error" {
			retryMessageCount++
		}
		if e.Level == zap.ErrorLevel {
			t.Fatal("Error should never happen!")
		}
		return nil
	})))

	// Define the function under test.
	mockRetry := MockRetry{countBeforeSuccess: 5}
	err := Retry(attempts, sleepTime, logger, mockRetry.mockFunction)
	assert.Equals(t, 2, retryMessageCount)
	// Check if the error matches the expected error.
	if err.Error() != fmt.Sprintf("after %d attempts, last error: %s", attempts, expectedErr) {
		t.Errorf("Unexpected error message. Expected: %s, Got: %s", expectedErr, err)
	}
}

func TestRetryWith2Retries(t *testing.T) {
	// Initialize test variables.
	retryMessageCount := 0
	attempts := 4
	sleepTime := 20 * time.Millisecond
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(e zapcore.Entry) error {
		if e.Message == "retrying after error" {
			retryMessageCount++
		}
		if e.Level == zap.ErrorLevel {
			t.Fatal("Error should never happen!")
		}
		return nil
	})))

	// Define the function under test.
	mockRetry := MockRetry{countBeforeSuccess: 4}
	err := Retry(attempts, sleepTime, logger, mockRetry.mockFunction)
	assert.Equals(t, 3, retryMessageCount)
	assert.Nil(t, err)
}

// Mocking log output
type LogCapture struct {
	Messages []string
}

func (lc *LogCapture) Write(p []byte) (n int, err error) {
	lc.Messages = append(lc.Messages, strings.TrimSpace(string(p)))
	return len(p), nil
}

// Helper function to reset the log capture
func captureLogs() (*LogCapture, func()) {
	logCapture := &LogCapture{}
	log.SetOutput(logCapture)
	return logCapture, func() {
		log.SetOutput(nil) // Restore default output after test
	}
}

func TestCloseWithErrorHandling_AllSuccessful(t *testing.T) {
	logCapture, reset := captureLogs()
	defer reset()

	CloseWithErrorHandling(
		func() error { return nil },
		func() error { return nil },
	)

	assert.Equals(t, 0, len(logCapture.Messages), "expected no log messages")
}

func TestCloseWithErrorHandling_OneError(t *testing.T) {
	logCapture, reset := captureLogs()
	defer reset()

	CloseWithErrorHandling(
		func() error { return errors.New("close error 1") },
		func() error { return nil },
	)

	assert.Equals(t, 1, len(logCapture.Messages), "expected a log message")
	assert.True(t, strings.Contains(logCapture.Messages[0], "error(s) occurred while closing files: close error 1"))
}

func TestCloseWithErrorHandling_MultipleErrors(t *testing.T) {
	logCapture, reset := captureLogs()
	defer reset()

	CloseWithErrorHandling(
		func() error { return errors.New("close error 1") },
		func() error { return errors.New("close error 2") },
	)

	assert.Equals(t, 1, len(logCapture.Messages), "expected a log message")
	assert.True(t, strings.Contains(logCapture.Messages[0], "error(s) occurred while closing files: close error 1; close error 2"))
}

func TestCloseWithErrorHandling_MixedSuccessAndErrors(t *testing.T) {
	logCapture, reset := captureLogs()
	defer reset()

	CloseWithErrorHandling(
		func() error { return nil },
		func() error { return errors.New("close error 1") },
		func() error { return nil },
		func() error { return errors.New("close error 2") },
	)

	assert.Equals(t, 1, len(logCapture.Messages), "expected a log message")
	assert.True(t, strings.Contains(logCapture.Messages[0], "error(s) occurred while closing files: close error 1; close error 2"))
}
