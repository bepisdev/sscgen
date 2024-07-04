package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
)

func TestPublicKey_NilPrivateKey(t *testing.T) {
	tests := []struct {
		name string
		priv any
		want any
	}{
		{
			name: "Nil RSA Private Key",
			priv: (*rsa.PrivateKey)(nil),
			want: nil,
		},
		{
			name: "Nil ECDSA Private Key",
			priv: (*ecdsa.PrivateKey)(nil),
			want: nil,
		},
		{
			name: "Nil Ed25519 Private Key",
			priv: (ed25519.PrivateKey)(nil),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("publicKey() did not panic for nil private key")
				}
			}()
			got := publicKey(tt.priv)
			if got != tt.want {
				t.Errorf("publicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
