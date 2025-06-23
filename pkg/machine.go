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
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	uniqueMACs := make(map[string]struct{})
	var macs []string

	for _, iface := range interfaces {
		// 仅保留 en 开头的接口（如 en0, en1, en2）
		if !strings.HasPrefix(iface.Name, "en") {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // 跳过回环接口
		}

		// 确保有 MAC 地址
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		// 去重
		if _, exists := uniqueMACs[mac]; !exists {
			uniqueMACs[mac] = struct{}{}
			macs = append(macs, mac)
		}
	}

	if len(macs) == 0 {
		return "", fmt.Errorf("未找到 en* 网络接口")
	}

	// 确保排序稳定
	sort.Strings(macs)
	fmt.Println(macs)

	// 生成 SHA256 指纹
	hash := sha256.Sum256([]byte(strings.Join(macs, "|")))
	return fmt.Sprintf("%x", hash), nil
}
