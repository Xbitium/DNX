// Package identity manages a DNX node's cryptographic identity.
//
// DNX PRINCIPLE: the ed25519 keypair *is* the machine. The FQDN
// (computer1.internal.dnxroute.com) is the human-readable handle that
// the registry binds to that key, first-come-first-served. Steal the
// name without the key and you're nobody — every control message and
// every ping is signed.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is what gets persisted to ~/.dnx/identity.json on first boot
// and loaded on every subsequent start.
type Identity struct {
	Name     string `json:"name"`     // this node's FQDN, e.g. "computer1.internal.dnxroute.com"
	Registry string `json:"registry"` // registry endpoint, e.g. "registry.dnxroute.com:4400"
	PubB64   string `json:"pubkey"`   // base64 ed25519 public key
	PrivB64  string `json:"privkey"`  // base64 ed25519 private key (mode 0600 file!)
}

// Priv decodes the stored private key for signing.
func (id *Identity) Priv() ed25519.PrivateKey {
	b, _ := base64.StdEncoding.DecodeString(id.PrivB64)
	return ed25519.PrivateKey(b)
}

// Dir returns the DNX config directory (~/.dnx), creating it if needed.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".dnx")
	// 0700: identity material lives here — owner-only.
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// LoadOrCreate loads the node identity, or generates a brand-new
// keypair on first boot. `name` and `registry` are only required on
// first boot; afterwards the persisted values win (pass "" to reuse).
func LoadOrCreate(name, registry string) (*Identity, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "identity.json")

	// ---- Existing identity? Load it. ----
	if b, err := os.ReadFile(path); err == nil {
		var id Identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, fmt.Errorf("corrupt identity file %s: %w", path, err)
		}
		// Allow overriding registry at runtime (e.g. moving VPS) without
		// touching the keypair. Name is immutable — it's bound to the key.
		if registry != "" {
			id.Registry = registry
		}
		return &id, nil
	}

	// ---- First boot: mint a new identity. ----
	if name == "" {
		return nil, fmt.Errorf("first boot: --name is required (e.g. --name computer1.internal.dnxroute.com)")
	}
	if registry == "" {
		registry = "registry.dnxroute.com:4400" // sensible DNX default
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		Name:     name,
		Registry: registry,
		PubB64:   base64.StdEncoding.EncodeToString(pub),
		PrivB64:  base64.StdEncoding.EncodeToString(priv),
	}
	b, _ := json.MarshalIndent(id, "", "  ")
	// 0600: private key inside — owner read/write only.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
