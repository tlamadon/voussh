package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/voussh/voussh/httpcred"
	"golang.org/x/crypto/ssh"
)

func TestParsePrivate(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	opensshBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"openssh": pem.EncodeToMemory(opensshBlock),
		"pkcs8":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	} {
		got, err := ParsePrivate(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got.Public().(ed25519.PublicKey), pub) {
			t.Errorf("%s: parsed a different key", name)
		}
	}

	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaBlock, err := ssh.MarshalPrivateKey(rsaKey, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	for name, data := range map[string][]byte{
		"passphrase-protected": pem.EncodeToMemory(encrypted),
		"rsa":                  pem.EncodeToMemory(rsaBlock),
		"public key":           ssh.MarshalAuthorizedKey(sshPub),
		"garbage":              []byte("not a key"),
		"empty":                nil,
	} {
		if _, err := ParsePrivate(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePublic(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := ssh.MarshalAuthorizedKey(sshPub)

	for name, data := range map[string][]byte{
		"openssh line":         line,
		"openssh with comment": append(bytes.TrimSpace(line), " voussh@host\n"...),
		"jwk":                  httpcred.MarshalPublicJWK(pub),
		"jwk with whitespace":  append([]byte("\n  "), httpcred.MarshalPublicJWK(pub)...),
	} {
		got, err := ParsePublic(data)
		if err != nil || !bytes.Equal(got, pub) {
			t.Errorf("%s: %v", name, err)
		}
	}

	privBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	for name, data := range map[string][]byte{
		"private key": pem.EncodeToMemory(privBlock),
		"rsa key":     ssh.MarshalAuthorizedKey(rsaPub),
		"private jwk": []byte(`{"kty":"OKP","crv":"Ed25519","x":"AA","d":"AA"}`),
		"garbage":     []byte("not a key"),
	} {
		if _, err := ParsePublic(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(path, []byte("nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(path); err == nil || !bytes.Contains([]byte(err.Error()), []byte(path)) {
		t.Errorf("LoadPrivate error = %v, want it to name the file", err)
	}
	if _, err := LoadPublic(path); err == nil || !bytes.Contains([]byte(err.Error()), []byte(path)) {
		t.Errorf("LoadPublic error = %v, want it to name the file", err)
	}
}
