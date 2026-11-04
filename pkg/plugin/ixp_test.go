package plugin

import "testing"

func TestIXFStateUp(t *testing.T) {
	for state, want := range map[string]bool{
		"active": true, "connected": true, "operational": true,
		"": false, "inactive": false, "pending": false, "Active": false,
	} {
		if got := IXFStateUp(state); got != want {
			t.Errorf("IXFStateUp(%q) = %v, want %v", state, got, want)
		}
	}
}
