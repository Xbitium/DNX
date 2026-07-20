// dnx: the user-facing CLI. This is where the DNX vision is VISIBLE:
// you type names, never IPs.
//
//	dnx ping computer2.internal.dnxroute.com
//	dnx status
//	dnx id
//
// It talks to the local dnxd agent over the localhost control API —
// the agent owns the identity key and the UDP socket; the CLI is a
// thin, disposable front end.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const defaultAPI = "http://127.0.0.1:4401" // dnxd's localhost control API

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {

	// ---------------- dnx ping <fqdn> ----------------
	case "ping":
		if len(os.Args) < 3 {
			fmt.Println("usage: dnx ping <name>   e.g. dnx ping computer2.internal.dnxroute.com")
			os.Exit(1)
		}
		target := os.Args[2]
		fmt.Printf("DNX ping %s (no IPs were typed in the making of this packet)\n", target)

		var r struct {
			Target      string  `json:"target"`
			RTTms       float64 `json:"rtt_ms"`
			Verified    bool    `json:"identity_verified"`
			Encrypted   bool    `json:"encrypted"`
			HandshakeMs float64 `json:"handshake_ms"`
			Error       string  `json:"error"`
		}
		get("/ping?name="+url.QueryEscape(target), &r)

		if r.Error != "" {
			fmt.Printf("FAIL: %s\n", r.Error)
			os.Exit(1)
		}
		// v0.2: encrypted=true means the payload was sealed with a key derived
		// from a handshake that only the OWNER OF THE NAME could have completed.
		fmt.Printf("reply from %s: rtt=%.2f ms  identity_verified=%v  encrypted=%v\n",
			r.Target, r.RTTms, r.Verified, r.Encrypted)
		// Only announce a handshake when one actually happened (>0.5ms).
		// A warm session reuses existing keys — that's the whole point of rekey-on-expiry.
		if r.HandshakeMs > 0.5 {
			fmt.Printf("  (new session: handshake took %.2f ms — subsequent pings reuse it)\n", r.HandshakeMs)
		} else {
			fmt.Printf("  (warm session reused — no handshake needed)\n")
		}

	// ---------------- dnx ping-plain <fqdn> (v0.1 path, for comparison) ----------------
	case "ping-plain":
		if len(os.Args) < 3 {
			fmt.Println("usage: dnx ping-plain <name>")
			os.Exit(1)
		}
		target := os.Args[2]
		fmt.Printf("DNX v0.1 PLAINTEXT ping %s (signed, but readable on the wire)\n", target)
		var r struct {
			Target   string  `json:"target"`
			RTTms    float64 `json:"rtt_ms"`
			Verified bool    `json:"identity_verified"`
			Error    string  `json:"error"`
		}
		get("/ping-plain?name="+url.QueryEscape(target), &r)
		if r.Error != "" {
			fmt.Printf("FAIL: %s\n", r.Error)
			os.Exit(1)
		}
		fmt.Printf("reply from %s: rtt=%.2f ms  identity_verified=%v  encrypted=false\n", r.Target, r.RTTms, r.Verified)

	// ---------------- dnx tunnel <fqdn> <local>:<remote> ----------------
	case "tunnel":
		if len(os.Args) < 4 {
			fmt.Println("usage: dnx tunnel <name> <localPort>:<remotePort>")
			fmt.Println("   eg: dnx tunnel host1.dnx.dnxroute.com 2222:22")
			fmt.Println("       then: ssh -p 2222 user@localhost   (rides DNX)")
			os.Exit(1)
		}
		target := os.Args[2]
		var localPort, remotePort int
		if _, err := fmt.Sscanf(os.Args[3], "%d:%d", &localPort, &remotePort); err != nil {
			fmt.Println("ports must look like 2222:22")
			os.Exit(1)
		}
		var r struct {
			Listening string `json:"listening"`
			Peer      string `json:"peer"`
			PeerPort  int    `json:"peer_port"`
			Error     string `json:"error"`
		}
		get(fmt.Sprintf("/tunnel?name=%s&local=%d&remote=%d",
			url.QueryEscape(target), localPort, remotePort), &r)
		if r.Error != "" {
			fmt.Printf("FAIL: %s\n", r.Error)
			os.Exit(1)
		}
		fmt.Printf("tunnel up: %s -> %s:%d\n", r.Listening, r.Peer, r.PeerPort)
		fmt.Printf("  traffic is sealed (ChaCha20-Poly1305), addressed by name, and NAT-traversing.\n")
		fmt.Printf("  try: ssh -p %d user@localhost\n", localPort)

	// ---------------- dnx status ----------------
	case "status":
		var raw map[string]string
		get("/status", &raw)
		fmt.Println("DNX node status")
		fmt.Println("  name:            ", raw["name"])
		fmt.Println("  registry:        ", raw["registry"])
		fmt.Println("  pubkey:          ", raw["pubkey"])
		fmt.Println("  public endpoint: ", raw["public_endpoint"], "(debug only — humans use names)")

	// ---------------- dnx id ----------------
	case "id":
		var raw map[string]string
		get("/status", &raw)
		// Short form: just who am I.
		fmt.Printf("%s (%s…)\n", raw["name"], first12(raw["pubkey"]))

	default:
		usage()
		os.Exit(1)
	}
}

// get calls the local agent API and decodes JSON into out.
func get(path string, out any) {
	resp, err := http.Get(defaultAPI + path)
	if err != nil {
		fmt.Println("cannot reach dnxd — is the agent running? (start it with: dnxd)")
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, out); err != nil {
		fmt.Printf("bad response from agent: %s\n", string(b))
		os.Exit(1)
	}
}

func first12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func usage() {
	fmt.Println(`dnx — names are the addresses

usage:
  dnx ping <fqdn>        encrypted, identity-verified ping by name (v0.2)
  dnx ping-plain <fqdn>  v0.1 plaintext ping — for wire comparison
  dnx tunnel <fqdn> <local>:<remote>
                         carry TCP over DNX (eg 2222:22, then ssh -p 2222)
  dnx status         show this node's DNX identity & registry
  dnx id             short identity line`)
}
