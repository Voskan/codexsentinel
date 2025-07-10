// Package logx provides a structured logger for CodexSentinel.
package logx

import (
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.SugaredLogger
	once         sync.Once
)

// Init initializes the global logger.
// Use `dev=true` for human-readable console logs with colors.
func Init(dev bool) error {
	var (
		cfg zap.Config
		err error
	)

	if dev {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "timestamp"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}

	logger, err := cfg.Build()
	if err != nil {
		return err
	}

	globalLogger = logger.Sugar()
	return nil
}

// L returns the global structured logger.
//
// You must call logx.Init() before using this.
func L() *zap.SugaredLogger {
	once.Do(func() {
		_ = Init(true) // fallback to dev mode if Init wasn't called
	})
	return globalLogger
}

// Sync flushes the logger buffer before exiting.
func Sync() {
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}
