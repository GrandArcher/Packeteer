package main

import (
	"fmt"
	"net/netip"
)

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid address %q", s)
	}
	return a, nil
}
