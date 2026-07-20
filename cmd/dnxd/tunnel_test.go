package main

import "testing"

// TestTunnelDisabledByDefault: a node that was never told which ports to
// publish must refuse every tunnel. Fail closed, not open.
func TestTunnelDisabledByDefault(t *testing.T) {
	ports, err := parseTunnelPorts("")
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{tunnelPorts: ports}
	for _, p := range []int{22, 80, 4600, 5432} {
		if err := a.tunnelAllowed(p); err == nil {
			t.Fatalf("CRITICAL: port %d allowed on a node with no allowlist", p)
		}
	}
}

// TestOnlyListedPortsAreReachable is the actual protection. handleTunnelOpen
// dials whatever port the peer asks for, so everything not named must be
// refused — particularly loopback services the operator never meant to
// publish, like an admin API or a metrics endpoint.
func TestOnlyListedPortsAreReachable(t *testing.T) {
	ports, err := parseTunnelPorts("22")
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{tunnelPorts: ports}

	if err := a.tunnelAllowed(22); err != nil {
		t.Fatalf("port 22 was listed and should be permitted: %v", err)
	}
	// Ports that exist on the live nodes and must stay unreachable.
	for _, p := range []int{80, 443, 4400, 4401, 4500, 4600, 5432, 6379} {
		if err := a.tunnelAllowed(p); err == nil {
			t.Fatalf("CRITICAL: unlisted port %d was reachable", p)
		}
	}
}

func TestMultiplePortsAndWhitespace(t *testing.T) {
	ports, err := parseTunnelPorts(" 22 , 5432,8080 ")
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{tunnelPorts: ports}
	for _, p := range []int{22, 5432, 8080} {
		if err := a.tunnelAllowed(p); err != nil {
			t.Fatalf("port %d should be permitted: %v", p, err)
		}
	}
	if err := a.tunnelAllowed(8081); err == nil {
		t.Fatal("8081 was not listed and must be refused")
	}
}

func TestRejectsNonsensePortSpecs(t *testing.T) {
	for _, spec := range []string{"twenty-two", "22,abc", "0", "65536", "-1"} {
		if _, err := parseTunnelPorts(spec); err == nil {
			t.Fatalf("spec %q should have been rejected", spec)
		}
	}
}

// TestEmptyFieldsAreIgnored: trailing commas are a typo, not an instruction
// to open everything.
func TestEmptyFieldsAreIgnored(t *testing.T) {
	ports, err := parseTunnelPorts("22,,")
	if err != nil {
		t.Fatalf("trailing commas should be tolerated: %v", err)
	}
	if len(ports) != 1 || !ports[22] {
		t.Fatalf("expected exactly {22}, got %v", ports)
	}
}
