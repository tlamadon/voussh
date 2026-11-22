// Package keyfile reads Ed25519 keys from the on-disk formats voussh and vsh
// already use for SSH, so the keys behind HTTP credentials can be created and
// inspected with the same tools (ssh-keygen, voussh init) as everything else.
package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/tlamadon/voussh/httpcred"
	"golang.org/x/crypto/ssh"
)

// ParsePrivate parses an unencrypted Ed25519 private key in OpenSSH or PKCS#8
// PEM format.
func ParsePrivate(data []byte) (ed25519.PrivateKey, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("key is passphrase-protected; an unencrypted Ed25519 key is required")
		}
		return nil, err
	}
	switch key := raw.(type) {
	case *ed25519.PrivateKey:
		return *key, nil
	case ed25519.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("key is %T, want an Ed25519 key", raw)
	}
}

// ParsePublic parses an Ed25519 public key given either as an OpenSSH
// authorized_keys line ("ssh-ed25519 AAAA...") or as a JWK.
func ParsePublic(data []byte) (ed25519.PublicKey, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return httpcred.ParsePublicJWK(trimmed)
	}
	if bytes.Contains(trimmed, []byte("PRIVATE KEY")) {
		return nil, errors.New("expected a public key, got a private key")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(trimmed)
	if err != nil {
		return nil, fmt.Errorf("not an OpenSSH public key or a JWK: %w", err)
	}
	if _, isCert := parsed.(*ssh.Certificate); isCert {
		return nil, errors.New("expected a public key, got a certificate")
	}
	crypto, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("unsupported public key type")
	}
	pub, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %s, want ssh-ed25519", parsed.Type())
	}
	return pub, nil
}

// LoadPrivate reads and parses a private key file.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivate(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// LoadPublic reads and parses a public key file.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePublic(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}
