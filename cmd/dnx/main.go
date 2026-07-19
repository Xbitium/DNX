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

const defaultAPI = "http://127.0.0.1:4401"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {

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
		fmt.Printf("reply from %s: rtt=%.2f ms  identity_verified=%v  encrypted=%v\n",
			r.Target, r.RTTms, r.Verified, r.Encrypted)
		if r.HandshakeMs > 0.5 {
			fmt.Printf("  (new session: handshake took %.2f ms — subsequent pings reuse it)\n", r.HandshakeMs)
		} else {
			fmt.Printf("  (warm session reused — no handshake needed)\n")
		}

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

	case "status":
		var raw map[string]string
		get("/status", &raw)
		fmt.Println("DNX node status")
		fmt.Println("  name:            ", raw["name"])
		fmt.Println("  registry:        ", raw["registry"])
		fmt.Println("  pubkey:          ", raw["pubkey"])
		fmt.Println("  public endpoint: ", raw["public_endpoint"], "(debug only — humans use names)")

	case "id":
		var raw map[string]string
		get("/status", &raw)
		fmt.Printf("%s (%s…)\n", raw["name"], first12(raw["pubkey"]))

	default:
		usage()
		os.Exit(1)
	}
}

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
  dnx status         show this node's DNX identity & registry
  dnx id             short identity line`)
}
