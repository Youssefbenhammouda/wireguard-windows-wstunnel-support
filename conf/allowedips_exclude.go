/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"strings"
)

func (config *Config) ApplyWstunnelHostExclusions() error {
	if strings.TrimSpace(config.Interface.WstunnelHost) == "" {
		return nil
	}
	excludes, err := parseWstunnelHostExcludes(config.Interface.WstunnelHost)
	if err != nil {
		return err
	}
	if len(excludes) == 0 {
		return nil
	}
	log.Printf("WSTUNNEL_HOST excludes: %s", prefixListToString(excludes))

	for i := range config.Peers {
		if len(config.Peers[i].AllowedIPs) == 0 {
			continue
		}
		before := prefixListToString(config.Peers[i].AllowedIPs)
		config.Peers[i].AllowedIPs = subtractPrefixList(config.Peers[i].AllowedIPs, excludes)
		after := prefixListToString(config.Peers[i].AllowedIPs)
		if before != after {
			log.Printf("AllowedIPs updated for peer %d: %s -> %s", i+1, before, after)
		}
	}
	return nil
}

func parseWstunnelHostExcludes(s string) ([]netip.Prefix, error) {
	parts, err := splitCommaList(s)
	if err != nil {
		return nil, err
	}
	excludes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid WSTUNNEL_HOST prefix %q: %w", part, err)
			}
			excludes = append(excludes, p.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			excludes = append(excludes, prefixFromAddr(addr))
			continue
		}
		resolved, err := resolveHostname(part)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve WSTUNNEL_HOST %q: %w", part, err)
		}
		addr, err := netip.ParseAddr(resolved)
		if err != nil {
			return nil, fmt.Errorf("invalid resolved WSTUNNEL_HOST %q: %w", part, err)
		}
		excludes = append(excludes, prefixFromAddr(addr))
	}
	return excludes, nil
}

func splitCommaList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, fmt.Errorf("invalid list entry in %q", s)
		}
		out = append(out, trim)
	}
	return out, nil
}

func prefixFromAddr(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	return netip.PrefixFrom(addr, 128)
}

func subtractPrefixList(base []netip.Prefix, remove []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(base))
	for _, b := range base {
		fragments := []netip.Prefix{b.Masked()}
		for _, r := range remove {
			if b.Addr().Is4() != r.Addr().Is4() {
				continue
			}
			newFragments := make([]netip.Prefix, 0, len(fragments))
			for _, f := range fragments {
				newFragments = append(newFragments, subtractPrefix(f, r.Masked())...)
			}
			fragments = newFragments
		}
		out = append(out, fragments...)
	}
	return out
}

func subtractPrefix(base, remove netip.Prefix) []netip.Prefix {
	base = base.Masked()
	remove = remove.Masked()
	if !base.Overlaps(remove) {
		return []netip.Prefix{base}
	}
	if remove.Contains(base.Addr()) && remove.Bits() <= base.Bits() {
		return nil
	}
	if base.Bits() >= maxPrefixBits(base) {
		return []netip.Prefix{base}
	}
	left, right := splitPrefix(base)
	if remove.Overlaps(left) {
		return append(subtractPrefix(left, remove), right)
	}
	return append([]netip.Prefix{left}, subtractPrefix(right, remove)...)
}

func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits()
	if p.Addr().Is4() {
		addr := p.Addr().As4()
		v := binary.BigEndian.Uint32(addr[:])
		bit := uint32(1) << (31 - uint32(bits))
		right := v | bit
		var rightAddr [4]byte
		binary.BigEndian.PutUint32(rightAddr[:], right)
		return netip.PrefixFrom(p.Addr(), bits+1), netip.PrefixFrom(netip.AddrFrom4(rightAddr), bits+1)
	}
	addr := p.Addr().As16()
	setBit128(&addr, bits)
	return netip.PrefixFrom(p.Addr(), bits+1), netip.PrefixFrom(netip.AddrFrom16(addr), bits+1)
}

func setBit128(addr *[16]byte, bit int) {
	byteIndex := bit / 8
	bitIndex := 7 - (bit % 8)
	addr[byteIndex] |= 1 << bitIndex
}

func maxPrefixBits(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 32
	}
	return 128
}

func prefixListToString(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return ""
	}
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}
