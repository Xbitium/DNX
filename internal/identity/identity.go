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

type Identity struct {
	Name     string `json:"name"`
	Registry string `json:"registry"`
	PubB64   string `json:"pubkey"`
	PrivB64  string `json:"privkey"`
}

func (id *Identity) Priv() ed25519.PrivateKey {
	b, _ := base64.StdEncoding.DecodeString(id.PrivB64)
	return ed25519.PrivateKey(b)
}

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".dnx")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

func LoadOrCreate(name, registry string) (*Identity, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "identity.json")

	if b, err := os.ReadFile(path); err == nil {
		var id Identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, fmt.Errorf("corrupt identity file %s: %w", path, err)
		}
		if registry != "" {
			id.Registry = registry
		}
		return &id, nil
	}

	if name == "" {
		return nil, fmt.Errorf("first boot: --name is required (e.g. --name computer1.internal.dnxroute.com)")
	}
	if registry == "" {
		registry = "registry.dnxroute.com:4400"
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
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
