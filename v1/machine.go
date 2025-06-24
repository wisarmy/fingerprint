package v1

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"
)

// GetMachineFingerprint 基于物理网卡的 MAC 地址生成一个唯一的、稳定的机器指纹。
func GetMachineFingerprint() (string, error) {
	// 常见虚拟网络接口的前缀列表。
	// 这个列表可以根据具体环境进行扩展。
	// lo: 回环接口
	// veth: 虚拟以太网
	// docker: Docker 网桥
	// br-: 网桥
	// vmnet: VMWare
	// vboxnet: VirtualBox
	// tap: TAP 虚拟网络设备
	// tun: TUN 虚拟网络设备
	// ipsec: IPsec 隧道
	// ppp: 点对点协议
	// bond: 链路聚合
	// dummy: 虚拟接口
	// sit: IPv6-in-IPv4 隧道
	// wwan: 无线广域网 (通常是虚拟的)
	virtualNetPrefixes := []string{
		"lo", "veth", "docker", "br-", "vmnet", "vboxnet", "tap", "tun", "ipsec", "ppp", "bond", "dummy", "sit", "wwan",
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("获取网络接口失败: %w", err)
	}

	var physicalMACs []string
	uniqueMACs := make(map[string]struct{})

	for _, iface := range interfaces {
		// 1. 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 2. 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 3. 跳过没有硬件地址（MAC 地址）的接口
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		// 4. 跳过常见的虚拟接口前缀
		isVirtual := false
		for _, prefix := range virtualNetPrefixes {
			if strings.HasPrefix(strings.ToLower(iface.Name), prefix) {
				isVirtual = true
				break
			}
		}
		if isVirtual {
			continue
		}

		// 5. 如果 MAC 地址是唯一的，则添加它
		if _, exists := uniqueMACs[mac]; !exists {
			uniqueMACs[mac] = struct{}{}
			physicalMACs = append(physicalMACs, mac)
		}
	}

	if len(physicalMACs) == 0 {
		return "", fmt.Errorf("未找到合适的物理网络接口")
	}

	// 对 MAC 地址进行排序以确保顺序稳定
	sort.Strings(physicalMACs)

	// 连接 MAC 地址并生成 SHA256 哈希值
	hash := sha256.Sum256([]byte(strings.Join(physicalMACs, "|")))
	return fmt.Sprintf("%x", hash), nil
}
