// Command nodeagent is the single binary that runs both the device-side
// agent and the vendor-side control plane. The mode is chosen at runtime
// by --mode=agent|control followed by a positional verb.
//
// Phase 1 surface area:
//
//	nodeagent --mode=control keygen  --priv K --pub P
//	nodeagent --mode=control issue   --priv K --device D --customer C --ttl T --out L
//	nodeagent --mode=agent   verify  --pub P  --licence L
//
// All other verbs (renew, update-image, restart-container, status, etc.)
// arrive in later phases. Keep this file additive only — never break
// the contract above without bumping licence.SchemaVersion in lockstep.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"nodeagent/internal/licence"
)

// Exit codes are part of the public CLI contract — Phase 9's air-gap
// demo and any future scripts will branch on them.
const (
	exitOK            = 0
	exitUsage         = 1
	exitVerifyFailure = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("nodeagent", flag.ContinueOnError)
	var mode string
	fs.StringVar(&mode, "mode", "", "agent|control")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: nodeagent --mode=agent|control <verb> [flags]")
		fmt.Fprintln(fs.Output(), "verbs: control keygen | control issue | agent verify")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	rest := fs.Args()
	if mode == "" {
		fmt.Fprintln(os.Stderr, "missing --mode (want agent or control)")
		fs.Usage()
		return exitUsage
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "missing verb after --mode")
		fs.Usage()
		return exitUsage
	}

	verb, verbArgs := rest[0], rest[1:]
	switch mode {
	case "control":
		return runControl(verb, verbArgs)
	case "agent":
		return runAgent(verb, verbArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (want agent or control)\n", mode)
		return exitUsage
	}
}

func runControl(verb string, args []string) int {
	switch verb {
	case "keygen":
		return controlKeygen(args)
	case "issue":
		return controlIssue(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown control verb %q (want keygen or issue)\n", verb)
		return exitUsage
	}
}

func runAgent(verb string, args []string) int {
	switch verb {
	case "verify":
		return agentVerify(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown agent verb %q (want verify)\n", verb)
		return exitUsage
	}
}

func controlKeygen(args []string) int {
	fs := flag.NewFlagSet("control keygen", flag.ContinueOnError)
	privPath := fs.String("priv", "", "path to write private key (PEM, mode 0600)")
	pubPath := fs.String("pub", "", "path to write public key (PEM, mode 0644)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *privPath == "" || *pubPath == "" {
		fmt.Fprintln(os.Stderr, "control keygen: --priv and --pub are required")
		return exitUsage
	}

	// Refuse to clobber an existing private key. Rotating signing
	// material is a deliberate act — make the operator delete the old
	// key first so they're forced to notice.
	if _, err := os.Stat(*privPath); err == nil {
		fmt.Fprintf(os.Stderr, "refusing to overwrite existing private key at %s\n", *privPath)
		return exitUsage
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "stat %s: %v\n", *privPath, err)
		return exitUsage
	}

	pub, priv, err := licence.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate keypair: %v\n", err)
		return exitUsage
	}
	if err := licence.SavePrivateKey(*privPath, priv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	if err := licence.SavePublicKey(*pubPath, pub); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "wrote private key to %s and public key to %s\n", *privPath, *pubPath)
	return exitOK
}

func controlIssue(args []string) int {
	fs := flag.NewFlagSet("control issue", flag.ContinueOnError)
	privPath := fs.String("priv", "", "path to vendor private key (PEM)")
	deviceID := fs.String("device", "", "device id (any string for now; TPM-derived in Phase 2)")
	customerID := fs.String("customer", "", "customer id, e.g. spaider-prod-01")
	ttl := fs.Duration("ttl", 0, "licence duration from now, e.g. 30s, 5m, 168h")
	outPath := fs.String("out", "", "path to write signed licence JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *privPath == "" || *deviceID == "" || *customerID == "" || *ttl <= 0 || *outPath == "" {
		fmt.Fprintln(os.Stderr, "control issue: --priv, --device, --customer, --ttl (>0), --out are required")
		return exitUsage
	}

	priv, err := licence.LoadPrivateKey(*privPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		fmt.Fprintf(os.Stderr, "generate nonce: %v\n", err)
		return exitUsage
	}

	now := time.Now().UTC()
	l := licence.Licence{
		LicenceID:  uuid.NewString(),
		DeviceID:   *deviceID,
		CustomerID: *customerID,
		IssuedAt:   now,
		NotBefore:  now,
		ExpiresAt:  now.Add(*ttl),
		Version:    licence.SchemaVersion,
		Nonce:      hex.EncodeToString(nonceBytes),
	}

	signed, err := licence.Sign(l, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal envelope: %v\n", err)
		return exitUsage
	}
	if err := os.WriteFile(*outPath, raw, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write licence to %s: %v\n", *outPath, err)
		return exitUsage
	}
	fmt.Fprintf(os.Stderr,
		"issued licence %s (device=%s customer=%s expires=%s) -> %s\n",
		l.LicenceID, l.DeviceID, l.CustomerID,
		l.ExpiresAt.Format(time.RFC3339), *outPath,
	)
	return exitOK
}

func agentVerify(args []string) int {
	fs := flag.NewFlagSet("agent verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "path to vendor public key (PEM)")
	licPath := fs.String("licence", "", "path to signed licence JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *pubPath == "" || *licPath == "" {
		fmt.Fprintln(os.Stderr, "agent verify: --pub and --licence are required")
		return exitUsage
	}

	pub, err := licence.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	raw, err := os.ReadFile(*licPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read licence %s: %v\n", *licPath, err)
		return exitUsage
	}

	decoded, err := licence.Verify(raw, pub, time.Now().UTC())
	if err != nil {
		// Report the sentinel's canonical text so scripts can grep on
		// stable strings. The wrapped context (e.g. "unmarshal envelope: ...")
		// gets dropped here on purpose — keep stderr terse for now.
		for _, sentinel := range []error{
			licence.ErrExpired,
			licence.ErrNotYetValid,
			licence.ErrTampered,
			licence.ErrMalformed,
			licence.ErrUnsupportedVersion,
		} {
			if errors.Is(err, sentinel) {
				fmt.Fprintln(os.Stderr, sentinel.Error())
				return exitVerifyFailure
			}
		}
		fmt.Fprintln(os.Stderr, err)
		return exitVerifyFailure
	}

	out, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal decoded licence: %v\n", err)
		return exitUsage
	}
	fmt.Println(string(out))
	return exitOK
}
