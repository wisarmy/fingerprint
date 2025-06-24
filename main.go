package main

import (
	"fmt"
	"log"

	v1 "github.com/wisarmy/fingerprint/v1"
)

func main() {
	fingerprint, err := v1.GetMachineFingerprint()
	if err != nil {
		log.Fatalf("无法生成机器指纹: %v", err)
	}
	fmt.Println(fingerprint)
}
