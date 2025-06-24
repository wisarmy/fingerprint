package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	v1 "github.com/wisarmy/fingerprint/v1"
)

func main() {
	var logLevel = slog.LevelInfo // 默认日志级别
	if os.Getenv("GO_LOG") != "" {
		logLevel.UnmarshalText([]byte(os.Getenv("GO_LOG")))
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel, // 动态设置级别
	}))
	slog.SetDefault(logger)

	fingerprint, err := v1.GetMachineFingerprint()
	if err != nil {
		log.Fatalf("无法生成机器指纹: %v", err)
	}
	fmt.Println(fingerprint)
}
