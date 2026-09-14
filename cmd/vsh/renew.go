package main

// vsh renew is the machine counterpart to `vsh login`: it trades a voussh
// service token for a short-lived certificate with no browser, no prompts and
// no shell-session plumbing, so a systemd timer can run it as one command.
// It deliberately shares nothing with the interactive login flow.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func cmdRenew(args []string) {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	server := fs.String("server", "", "Server URL (default: $VSH_SERVER or the saved server)")
	tokenFile := fs.String("token-file", "", "File containing the service token (required)")
	keyPath := fs.String("key", "", "Private key to certify (default: ~/.ssh/id_ed25519); generated if missing")
	certPath := fs.String("cert", "", "Where to write the certificate (default: <key>-cert.pub)")
	fs.Parse(args)

	if *server != "" {
		serverURL = *server
	}
	if serverURL == "" {
		fmt.Println("No server configured. Use --server or set VSH_SERVER.")
		os.Exit(1)
	}
	if *tokenFile == "" {
		fmt.Println("--token-file is required")
		os.Exit(1)
	}
	if *keyPath == "" {
		homeDir, _ := os.UserHomeDir()
		*keyPath = filepath.Join(homeDir, ".ssh", "id_ed25519")
	}
	if *certPath == "" {
		*certPath = *keyPath + "-cert.pub"
	}

	if err := renew(serverURL, *tokenFile, *keyPath, *certPath); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

func renew(server, tokenFile, keyPath, certPath string) error {
	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		return fmt.Errorf("token file %s is empty", tokenFile)
	}

	pubKeyData, err := ensureKeyPair(keyPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, server+"/sign", bytes.NewReader(pubKeyData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact %s: %w", server, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" || len(msg) > 200 {
			msg = resp.Status
		}
		return fmt.Errorf("signing failed: %s", msg)
	}

	// Refuse to overwrite the certificate file with anything that is not a
	// certificate, e.g. an error page from a proxy in front of the server.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		return fmt.Errorf("server response is not a certificate: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("server response is not a certificate")
	}

	if err := writeFileAtomic(certPath, body, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	fmt.Printf("Certificate written to %s (key id %s, principals %s, valid until %s)\n",
		certPath, cert.KeyId, strings.Join(cert.ValidPrincipals, ","),
		time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
	return nil
}

// ensureKeyPair returns the authorized_keys line for keyPath's public key,
// generating a new ed25519 key pair if the private key does not exist yet.
func ensureKeyPair(keyPath string) ([]byte, error) {
	pubPath := keyPath + ".pub"

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, fmt.Errorf("failed to write private key: %w", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		pubBytes := ssh.MarshalAuthorizedKey(sshPub)
		if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
			return nil, fmt.Errorf("failed to write public key: %w", err)
		}
		fmt.Printf("Generated new key pair at %s\n", keyPath)
		return pubBytes, nil
	}

	if data, err := os.ReadFile(pubPath); err == nil {
		return data, nil
	}

	// The private key exists but its .pub is missing: derive it.
	privData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(privData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key %s (an encrypted key needs its .pub next to it): %w", keyPath, err)
	}
	return ssh.MarshalAuthorizedKey(signer.PublicKey()), nil
}

// writeFileAtomic writes via a temp file + rename in the target directory, so
// a renewal that dies mid-write can never leave a truncated certificate for
// ssh to trip over.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
