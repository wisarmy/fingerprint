package main

import (
	"fmt"
	"log"

	"github.com/wisarmy/fingerprint/pkg"
)

func main() {
	fingerprint, err := pkg.GetMachineFingerprint()
	if err != nil {
		log.Fatalf("无法生成机器指纹: %v", err)
	}
	fmt.Println(fingerprint)
}
