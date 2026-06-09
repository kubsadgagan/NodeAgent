// Command nodeagent seals and unseals data against the local TPM 2.0
// chip. Phase 2 of the nodeagent POC — demonstrates "sealed bytes
// are bound to this physical TPM; copying the blob to another machine
// produces noise."
//
//	nodeagent --mode=agent seal   --in <plaintext>  --out <sealed>
//	nodeagent --mode=agent unseal --in <sealed>     --out <plaintext|->
//
// Exit codes form the public contract:
//
//	0  success
//	1  usage / IO error
//	2  TPM seal or unseal failed (likely wrong TPM, malformed blob, or
//	   no /dev/tpmrm0 on this host)
//
// Phase 2 only exposes these two verbs. The licence signing/verifying
// verbs live in phase-1/ as a separate standalone project.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"nodeagent/internal/tpm"
)

const (
	exitOK         = 0
	exitUsage      = 1
	exitTPMFailure = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("nodeagent", flag.ContinueOnError)
	var mode string
	fs.StringVar(&mode, "mode", "", "must be \"agent\"")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: nodeagent --mode=agent <verb> [flags]")
		fmt.Fprintln(fs.Output(), "verbs: seal | unseal")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	rest := fs.Args()
	if mode != "agent" {
		fmt.Fprintf(os.Stderr, "phase-2 nodeagent only supports --mode=agent (got %q)\n", mode)
		fs.Usage()
		return exitUsage
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "missing verb after --mode=agent")
		fs.Usage()
		return exitUsage
	}

	verb, verbArgs := rest[0], rest[1:]
	switch verb {
	case "seal":
		return agentSeal(verbArgs)
	case "unseal":
		return agentUnseal(verbArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown verb %q (want seal or unseal)\n", verb)
		return exitUsage
	}
}

func agentSeal(args []string) int {
	fs := flag.NewFlagSet("agent seal", flag.ContinueOnError)
	inPath := fs.String("in", "", "path to plaintext input")
	outPath := fs.String("out", "", "path to sealed output (will be created mode 0600)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "agent seal: --in and --out are required")
		return exitUsage
	}

	plaintext, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *inPath, err)
		return exitUsage
	}

	sealed, err := tpm.Seal(plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitTPMFailure
	}

	if err := os.WriteFile(*outPath, sealed, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
		return exitUsage
	}

	fmt.Fprintf(os.Stderr,
		"sealed %d-byte plaintext into %d-byte blob at %s\n",
		len(plaintext), len(sealed), *outPath,
	)
	return exitOK
}

func agentUnseal(args []string) int {
	fs := flag.NewFlagSet("agent unseal", flag.ContinueOnError)
	inPath := fs.String("in", "", "path to sealed input")
	outPath := fs.String("out", "", "path to plaintext output (\"-\" for stdout)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "agent unseal: --in and --out are required")
		return exitUsage
	}

	sealed, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *inPath, err)
		return exitUsage
	}

	plaintext, err := tpm.Unseal(sealed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitTPMFailure
	}

	if *outPath == "-" {
		if _, err := os.Stdout.Write(plaintext); err != nil {
			fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
			return exitUsage
		}
		return exitOK
	}

	if err := os.WriteFile(*outPath, plaintext, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
		return exitUsage
	}

	fmt.Fprintf(os.Stderr,
		"unsealed %d-byte blob from %s -> %d-byte plaintext at %s\n",
		len(sealed), *inPath, len(plaintext), *outPath,
	)
	return exitOK
}
