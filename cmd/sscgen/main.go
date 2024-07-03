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
  printVersion bool
  printUsage bool
)


// Initialize CLI flags
func init() {
  flag.StringVarP(&host, "host", "H", "", "Comma-separated hostnames and IPs to generate a certificate for")
  flag.StringVarP(&validFrom, "start-date", "s", "", "Set creation date (formatted as Jan 1 15:04:05 2011)")
  flag.DurationVarP(&validFor, "duration", 365*24*time.Hour, "Duration that certificate is valid for")
  flag.BoolVarP(&isCA, "is-ca", "c", false, "Certificate is its own Certificate Authority")
  flag.IntVarP(&ecdsaCurve, "rsa-bits", "b", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
  flag.StringVarP(&ecdsaCurve, "ecdsa-curve", "e", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
  flag.BoolVar(&ed25519Key, "ed25519", false, "Generate an Ed25519 key")
  flag.BoolVarP(&flagVersion, "version", "v", false, "Print version information")
  flag.BoolVarP(&printUsage, "help", "h", false, "Print usage information")
}

func generatePublicKey(priv any) any {
  // TODO: Generate public key  
}

func main() {}
