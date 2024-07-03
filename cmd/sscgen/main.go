package main

import (
  flag "github.com/spf13/pflag"
  "time"
)

var (
	host string
	validFrom string
	validFor *time.Duration
	isCA  bool
	rsaBits int
	ecdsaCurve string
	ed25519Key bool
)


// Initialize CLI flags
func init() {
  // TODO: host flag StringVarP
  // TODO: validFrom flag StringVarP
  // TODO: validFor flag DurationVarP
  // TODO: isCA flag BoolVarP
  // TODO: rsaBits flag IntVarP
  // TODO: ecdsaCurve StringVarP
  // TODO: ed25519Key BoolVarP
}

func generatePublicKey(priv any) any {
  // TODO: Generate public key  
}

func main() {}
