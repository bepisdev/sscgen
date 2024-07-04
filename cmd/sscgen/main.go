package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
)

// Global constant to hold program version
const SSCGEN_VERSION = "0.0.1"

// host is a global variable that holds the comma-separated hostnames and IPs to generate a certificate for.
var host string

// validFrom is a global variable that holds the creation date of the certificate.
// It is formatted as Jan 1 15:04:05 2011.
var validFrom string

// validFor is a global variable that holds the duration that the certificate is valid for.
// The default value is 365*24*time.Hour.
var validFor time.Duration

// isCA is a global variable that indicates whether the certificate is its own Certificate Authority.
var isCA bool

// rsaBits is a global variable that holds the size of RSA key to generate.
// It is ignored if --ecdsa-curve is set. The default value is 2048.
var rsaBits int

// ecdsaCurve is a global variable that holds the ECDSA curve to use to generate a key.
// Valid values are P224, P256 (recommended), P384, P521.
var ecdsaCurve string

// ed25519Key is a global variable that indicates whether to generate an Ed25519 key.
var ed25519Key bool

// printVersion is a global variable that indicates whether to print version information.
var printVersion bool

// printUsage is a global variable that indicates whether to print usage information.
var printUsage bool

// init initializes the CLI flags for the sscgen tool.
func init() {
	// host is a global variable that holds the comma-separated hostnames and IPs to generate a certificate for.
	flag.StringVarP(&host, "host", "H", "", "Comma-separated hostnames and IPs to generate a certificate for")

	// validFrom is a global variable that holds the creation date of the certificate.
	// It is formatted as Jan 1 15:04:05 2011.
	flag.StringVarP(&validFrom, "start-date", "s", "", "Set creation date (formatted as Jan 1 15:04:05 2011)")

	// validFor is a global variable that holds the duration that the certificate is valid for.
	// The default value is 365*24*time.Hour.
	flag.DurationVarP(&validFor, "duration", "d", 365*24*time.Hour, "Duration that certificate is valid for")

	// isCA is a global variable that indicates whether the certificate is its own Certificate Authority.
	flag.BoolVarP(&isCA, "is-ca", "c", false, "Certificate is its own Certificate Authority")

	// rsaBits is a global variable that holds the size of RSA key to generate.
	// It is ignored if --ecdsa-curve is set. The default value is 2048.
	flag.IntVarP(&rsaBits, "rsa-bits", "b", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")

	// ecdsaCurve is a global variable that holds the ECDSA curve to use to generate a key.
	// Valid values are P224, P256 (recommended), P384, P521.
	flag.StringVarP(&ecdsaCurve, "ecdsa-curve", "e", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")

	// ed25519Key is a global variable that indicates whether to generate an Ed25519 key.
	flag.BoolVar(&ed25519Key, "ed25519", false, "Generate an Ed25519 key")

	// printVersion is a global variable that indicates whether to print version information.
	flag.BoolVarP(&printVersion, "version", "v", false, "Print version information")

	// printUsage is a global variable that indicates whether to print usage information.
	flag.BoolVarP(&printUsage, "help", "h", false, "Print usage information")
}

func main() {
	flag.Parse()

	// Print version if flag is present
	if printVersion {
		fmt.Printf("%s\n", SSCGEN_VERSION)
		os.Exit(0)
	}

	// Print usage if flag is present
	if printUsage {
		flag.Usage()
		os.Exit(0)
	}

	// Sanity check host list
	if len(host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	// Generate private key based on --ecdsa-curve
	var priv any
	var err error

	switch ecdsaCurve {
	case "":
		if ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized elliptic curve: %q", ecdsaCurve)
	}

	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			log.Fatalf("Failed to parse creation date: %v", err)
		}
	}

	notAfter := notBefore.Add(validFor)

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	// Put together certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Set CA flag
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate file
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Print("wrote cert.pem\n")

	// Write key file
	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}

	log.Print("wrote key.pem\n")

	// Exit successfully
	os.Exit(0)
}
