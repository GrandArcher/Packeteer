package oop

import (
	"strings"
	"testing"
)

func TestResolveCommand(t *testing.T) {
	tests := []struct{ dir, cmd, want, wantErr string }{
		{"/etc/packeteer/plugins", "a.sh", "/etc/packeteer/plugins/a.sh", ""},
		{"/etc/packeteer/plugins", "sub/../a.sh", "/etc/packeteer/plugins/a.sh", ""},
		{"/etc/packeteer/plugins", "/opt/x", "/opt/x", ""},
		{"/etc/packeteer/plugins", "../x", "", "escapes"},
		{"", "a.sh", "", "no plugin dir"},
		{"/p", "", "", "required"},
	}
	for _, tt := range tests {
		got, err := ResolveCommand(tt.dir, tt.cmd)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%q: err = %v", tt.cmd, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%q: got %q, %v", tt.cmd, got, err)
		}
	}
}
