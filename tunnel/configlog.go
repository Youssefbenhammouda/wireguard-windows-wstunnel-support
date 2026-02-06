/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func allowedIPsSummary(conf *conf.Config) string {
	if conf == nil {
		return ""
	}
	parts := make([]string, 0, len(conf.Peers))
	for i, peer := range conf.Peers {
		if len(peer.AllowedIPs) == 0 {
			continue
		}
		ips := make([]string, len(peer.AllowedIPs))
		for j, ip := range peer.AllowedIPs {
			ips[j] = ip.String()
		}
		parts = append(parts, fmt.Sprintf("peer %d: %s", i+1, strings.Join(ips, ", ")))
	}
	return strings.Join(parts, "; ")
}
