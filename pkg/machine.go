package pkg

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"
)

// GetMachineFingerprint 基于网卡 MAC 地址生成一个唯一的、稳定的机器指纹。
func GetMachineFingerprint() (string, error) {
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var macs []string
	for _, iface := range interfaces {
		// 我们只关心硬件地址，且排除环回接口
		if iface.Flags&net.FlagLoopback == 0 && iface.HardwareAddr.String() != "" {
			macs = append(macs, iface.HardwareAddr.String())
		}
	}

	if len(macs) == 0 {
		return "", fmt.Errorf("未找到合适的网络接口")
	}

	// fmt.Printf("macs: %v\n", macs)

	// 排序以确保每次生成的顺序一致
	sort.Strings(macs)

	// 将所有 MAC 地址连接成一个字符串，并使用 SHA256 哈希来创建指纹
	hash := sha256.Sum256([]byte(strings.Join(macs, "|")))
	return fmt.Sprintf("%x", hash), nil
}
