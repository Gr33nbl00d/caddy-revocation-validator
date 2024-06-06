package utils

import (
	"fmt"
	"go.uber.org/zap"
	"log"
	"time"
)

func Retry(attempts int, sleep time.Duration, logger *zap.Logger, f func() error) (err error) {
	for i := 0; ; i++ {
		err = f()
		if err == nil {
			return
		}

		if i >= (attempts - 1) {
			break
		}
		time.Sleep(sleep)
		logger.Debug("retrying after error", zap.Error(err))
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

func CloseWithErrorHandling(closers ...func() error) {
	var err error
	for _, closeFn := range closers {
		if cerr := closeFn(); cerr != nil {
			if err == nil {
				err = cerr
			} else {
				err = fmt.Errorf("%v; %v", err, cerr)
			}
		}
	}
	if err != nil {
		log.Printf("error(s) occurred while closing files: %v", err)
	}
}
