# Self-Signed Certificate Generator (sscgen)

`sscgen` is a command-line tool written in Go that generates self-signed X.509 certificates for testing or development purposes.

## Installation

### From Source

1. Install Go (if not already installed) by following the instructions at https://golang.org/doc/install.

2. Clone the `sscgen` repository:

   ```sh
   git clone https://github.com/bepisdev/sscgen.git
   cd sscgen
   ```

3. Build the `sscgen` binary:

   ```sh
   make
   ```

4. Move the `sscgen` binary to a directory included in your system's `PATH` (e.g., `/usr/local/bin`):

   ```sh
   sudo mv dist/sscgen /usr/local/bin
   ```

## Usage

To generate a self-signed certificate, run the `sscgen` command followed by the desired options:

```sh
sscgen --host example.com --start-date "Jan 1 15:04:05 2024" --duration 365 --rsa-bits 4096 --ecdsa-curve P256 --ed25519
```

### Options

- `--host`: Comma-separated list of hostnames and IP addresses for which the certificate should be valid.
- `--start-date`: Creation date of the certificate (default: current date).
- `--duration`: Duration for which the certificate should be valid (default: 365 days).
- `--rsa-bits`: Size of the RSA key to generate (default: 2048 bits).
- `--ecdsa-curve`: ECDSA curve to use for generating the key (default: P256).
- `--ed25519`: Generate an Ed25519 key instead of an RSA or ECDSA key.

### Output

The `sscgen` tool will generate two files: `cert.pem` and `key.pem`.

- `cert.pem`: Contains the self-signed X.509 certificate in PEM format.
- `key.pem`: Contains the private key in PKCS#8 format.

### Examples

Generate a self-signed certificate valid for `example.com` and `127.0.0.1` for 1 year:

```sh
sscgen --host example.com,127.0.0.1 --duration 365
```

Generate a self-signed certificate using an Ed25519 key:

```sh
sscgen --host example.com --ed25519
```

## License

This project is licensed under the GNU GPLv3 License.
