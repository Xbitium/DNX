package main

// Fetching the namespace table from its authority.
//
// Until now every router re-derived identifiers from an ordered name list in
// its own config, and stayed correct only while every config on the network
// listed the same names in the same order — a hazard section 10.3 records,
// and one that fails silently (a disagreeing router forwards confidently to
// the wrong place). This file replaces derivation with receipt: the router
// asks the registry — the party that actually OWNS the namespace — for the
// table it allocated, verifies the signature, and grafts the entries with
// the exact identifiers the authority assigned. Order cannot matter,
// because nothing is derived.
//
// The config list is kept as a fallback for a router with no registry
// configured, so nothing already deployed changes behaviour by surprise.

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"dnx/internal/nspath"
	"dnx/internal/proto"
	"dnx/internal/secure"
)

// fetchNamespace asks the registry for its allocation table once, verifies
// it, and returns the entries. The caller decides what to do with them.
func fetchNamespace(registryAddr, registryKey string, timeout time.Duration) ([]nspath.Entry, string, error) {
	raddr, err := net.ResolveUDPAddr("udp", registryAddr)
	if err != nil {
		return nil, "", fmt.Errorf("registry address: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	nonce := secure.NewNonce()
	req := &proto.Message{Kind: proto.KindNamespace, TS: time.Now().UnixMilli(), Nonce: nonce}
	if _, err := conn.Write(proto.Encode(req)); err != nil {
		return nil, "", err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, "", fmt.Errorf("no answer from %s: %w", registryAddr, err)
	}
	m, err := proto.Decode(buf[:n])
	if err != nil {
		return nil, "", err
	}
	if m.Kind == proto.KindError {
		return nil, "", fmt.Errorf("registry refused: %s", m.Info)
	}
	if m.Kind != proto.KindNamespaceResp {
		return nil, "", fmt.Errorf("unexpected %s from registry", m.Kind)
	}
	// The answer must be for THIS question. An unsolicited or replayed
	// table is an attacker choosing which past to serve us.
	if m.Nonce != nonce {
		return nil, "", fmt.Errorf("namespace answer does not echo our nonce, refusing it")
	}
	// And it must be signed by the registry we were told to trust. An
	// unsigned table is a routing plan from whoever answered fastest.
	if err := proto.VerifyDetached(registryKey,
		proto.NamespaceBytes(m.Zone, m.Info, m.TS, m.Nonce), m.Sig); err != nil {
		return nil, "", fmt.Errorf("namespace table signature: %w", err)
	}

	var entries []nspath.Entry
	if err := json.Unmarshal([]byte(m.Info), &entries); err != nil {
		return nil, "", fmt.Errorf("namespace table: %w", err)
	}
	return entries, m.Zone, nil
}

// adoptNamespace grafts a verified table into the daemon's tree. Grafting —
// exact identifiers, any order — is the whole point: this router now holds
// what the authority allocated, not what it happened to derive.
//
// A conflicting entry aborts the adoption rather than skipping the entry: a
// table that contradicts what this router already routes by means either the
// registry restarted from the wrong state or this router did, and partial
// agreement about identifiers is indistinguishable from disagreement.
func (d *daemon) adoptNamespace(entries []nspath.Entry) error {
	for _, e := range entries {
		if err := d.ns.Graft(e.Name, e.Path); err != nil {
			return fmt.Errorf("entry %s -> [%s]: %w", e.Name, e.Path, err)
		}
	}
	return nil
}

// syncNamespace fetches, adopts, and logs — one round of "believe the
// authority". Used at startup and then periodically, so a name registered
// after this router booted becomes routable without a restart.
func (d *daemon) syncNamespace(registryAddr, registryKey string) error {
	entries, zoneName, err := fetchNamespace(registryAddr, registryKey, 5*time.Second)
	if err != nil {
		return err
	}
	if err := d.adoptNamespace(entries); err != nil {
		return err
	}
	log.Printf("namespace: %d entr%s adopted from %s (zone %q)",
		len(entries), map[bool]string{true: "y", false: "ies"}[len(entries) == 1], registryAddr, zoneName)
	return nil
}

// namespaceRefreshLoop keeps the table current. Failures are logged and
// tolerated — the router keeps forwarding by the last table it verified,
// which is strictly better than forgetting a working table because one
// refresh timed out.
func (d *daemon) namespaceRefreshLoop(registryAddr, registryKey string, every time.Duration) {
	for range time.Tick(every) {
		if err := d.syncNamespace(registryAddr, registryKey); err != nil {
			log.Printf("namespace refresh: %v (keeping the previous table)", err)
		}
	}
}
