package trafficcontrol

import "testing"

func TestClassIDForPeer(t *testing.T) {
	cases := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{"10.0.0.2", "1:2", false},
		{"10.0.0.254", "1:254", false},
		{"10.8.0.42", "1:42", false},
		{"10.0.0.1", "", true},   // gateway reserved
		{"10.0.0.0", "", true},   // network reserved
		{"10.0.0.255", "", true}, // broadcast out of 2-254
		{"not-an-ip", "", true},
		{"::1", "", true}, // IPv6 rejected
	}
	for _, tc := range cases {
		got, err := classIDForPeer(tc.ip)
		if tc.wantErr {
			if err == nil {
				t.Errorf("classIDForPeer(%q): expected error, got %q", tc.ip, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("classIDForPeer(%q): unexpected error %v", tc.ip, err)
		}
		if got != tc.want {
			t.Errorf("classIDForPeer(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// RemoveLimit must be idempotent: removing a peer with no rule returns nil
// (peer-removal cleanup calls it unconditionally) and never shells out to tc.
func TestRemoveLimitIdempotent(t *testing.T) {
	m := &Manager{
		interfaceName: "wg-test",
		rules:         map[string]*TCRule{},
	}
	if err := m.RemoveLimit("10.0.0.50"); err != nil {
		t.Errorf("RemoveLimit on absent rule should be nil, got %v", err)
	}
}
