package utils

import (
	"errors"
	"fmt"
	"github.com/smallstep/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
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
