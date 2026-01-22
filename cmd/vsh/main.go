package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	serverURL string
	vshDir    string
)

func init() {
	homeDir, _ := os.UserHomeDir()
	vshDir = filepath.Join(homeDir, ".vsh")
	os.MkdirAll(vshDir, 0700)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// Load server URL from config
	serverURL = os.Getenv("VSH_SERVER")
	if serverURL == "" {
		configPath := filepath.Join(vshDir, "config")
		if data, err := os.ReadFile(configPath); err == nil {
			serverURL = strings.TrimSpace(string(data))
		}
	}

	switch cmd {
	case "login":
		cmdLogin(args)
	case "logout":
		cmdLogout()
	case "status":
		cmdStatus()
	case "ssh":
		cmdSSH(args)
	case "pubkey":
		cmdPubkey()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: vsh <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  login   Login and obtain SSH certificate")
	fmt.Println("  logout  Remove SSH certificate and clear config")
	fmt.Println("  status  Show current login status")
	fmt.Println("  ssh     SSH to a host using certificate")
	fmt.Println("  pubkey  Get CA public key from server")
}

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", serverURL, "Server URL")
	role := fs.String("role", "", "Role to assume (default: user's default role)")
	fs.Parse(args)

	if *server == "" {
		fmt.Println("Server URL required (use --server or VSH_SERVER env)")
		os.Exit(1)
	}
	serverURL = *server

	// Get user's SSH public key
	homeDir, _ := os.UserHomeDir()
	pubKeyPath := filepath.Join(homeDir, ".ssh", "id_ed25519.pub")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Printf("Failed to read SSH public key (%s): %v\n", pubKeyPath, err)
		fmt.Println("Please generate an SSH key with: ssh-keygen -t ed25519")
		os.Exit(1)
	}

	// Base64 encode the public key for URL safety
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(pubKeyData)

	// Start local callback server
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Printf("Failed to start local server: %v\n", err)
		os.Exit(1)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	resultChan := make(chan loginResult, 1)

	server_mux := http.NewServeMux()
	httpServer := &http.Server{Handler: server_mux}

	server_mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		certB64 := r.URL.Query().Get("cert")
		roleReturned := r.URL.Query().Get("role")

		if certB64 == "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html>
<html><body style="font-family: system-ui; text-align: center; padding: 50px;">
<h2 style="color: #c00;">Login Failed</h2>
<p>No certificate received.</p>
</body></html>`)
			resultChan <- loginResult{err: fmt.Errorf("no certificate received")}
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html><body style="font-family: system-ui; text-align: center; padding: 50px;">
<h2 style="color: #0a0;">Login Successful!</h2>
<p>You can close this window and return to your terminal.</p>
</body></html>`)

		resultChan <- loginResult{cert: certB64, role: roleReturned}
	})

	go httpServer.Serve(listener)

	// Build login URL with parameters
	loginURL := fmt.Sprintf("%s/login?cli_port=%d&pubkey=%s", serverURL, port, pubKeyB64)
	if *role != "" {
		loginURL += "&role=" + *role
	}

	fmt.Printf("DEBUG: CLI listening on port: %d\n", port)
	fmt.Printf("DEBUG: Public key base64 length: %d\n", len(pubKeyB64))

	// Warn about HSTS for Tailscale domains
	if strings.HasPrefix(loginURL, "http://") && strings.Contains(loginURL, ".ts.net") {
		fmt.Println("⚠️  Warning: Tailscale domains (.ts.net) require HTTPS due to browser HSTS policies.")
		fmt.Println("   Your browser will automatically redirect to HTTPS even though you specified HTTP.")
		fmt.Println("   Either configure TLS on the server or use localhost/IP address instead.")
		fmt.Println()
	}

	fmt.Println("Opening browser for authentication...")
	fmt.Printf("Login URL: %s\n", loginURL)
	openBrowser(loginURL)
	fmt.Printf("Waiting for callback on localhost:%d...\n", port)
	fmt.Println("Note: The callback only works if the browser is on the same machine as this CLI.")
	fmt.Println("      If using remote/Tailscale access, you may need to manually copy the certificate from the browser.")

	// Wait for result
	select {
	case result := <-resultChan:
		httpServer.Close()
		if result.err != nil {
			fmt.Printf("Login failed: %v\n", result.err)
			os.Exit(1)
		}

		// Decode and save certificate
		certData, err := base64.RawURLEncoding.DecodeString(result.cert)
		if err != nil {
			fmt.Printf("Failed to decode certificate: %v\n", err)
			os.Exit(1)
		}

		// Write certificate to ~/.ssh/id_ed25519-cert.pub
		certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
		if err := os.WriteFile(certPath, certData, 0644); err != nil {
			fmt.Printf("Failed to save certificate: %v\n", err)
			os.Exit(1)
		}

		// Save server config
		configPath := filepath.Join(vshDir, "config")
		os.WriteFile(configPath, []byte(serverURL), 0600)

		fmt.Printf("Login successful! Role: %s\n", result.role)
		fmt.Printf("Certificate saved to: %s\n", certPath)

	case <-time.After(5 * time.Minute):
		httpServer.Close()
		fmt.Println("Login timeout. Please try again.")
		os.Exit(1)
	}
}

type loginResult struct {
	cert string
	role string
	err  error
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		fmt.Printf("Please open this URL in your browser:\n%s\n", url)
		return
	}
	cmd.Run()
}

func cmdLogout() {
	homeDir, _ := os.UserHomeDir()
	certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
	configPath := filepath.Join(vshDir, "config")

	// Remove certificate
	if err := os.Remove(certPath); err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Failed to remove certificate: %v\n", err)
		}
	} else {
		fmt.Println("Certificate removed")
	}

	// Remove server config
	if err := os.Remove(configPath); err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Failed to remove config: %v\n", err)
		}
	} else {
		fmt.Println("Server config cleared")
	}

	fmt.Println("Logged out successfully")
}

func cmdStatus() {
	homeDir, _ := os.UserHomeDir()
	certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Println("No SSH certificate found. Run: vsh login")
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		fmt.Println("Invalid certificate. Run: vsh login")
		return
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		fmt.Println("Not a certificate. Run: vsh login")
		return
	}

	// Parse KeyId (format: email@role)
	keyId := cert.KeyId
	email := keyId
	role := ""
	if idx := strings.LastIndex(keyId, "@"); idx != -1 {
		// Check if it looks like an email (has @ before another @)
		firstAt := strings.Index(keyId, "@")
		if firstAt != idx {
			email = keyId[:idx]
			role = keyId[idx+1:]
		}
	}

	fmt.Printf("Logged in as: %s\n", email)
	if role != "" {
		fmt.Printf("Role: %s\n", role)
	}
	fmt.Printf("Principals: %s\n", strings.Join(cert.ValidPrincipals, ", "))

	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	remaining := time.Until(validBefore)

	if remaining > 0 {
		fmt.Printf("Valid: %s to %s (%v remaining)\n",
			validAfter.Format("15:04"),
			validBefore.Format("15:04"),
			remaining.Round(time.Minute))
	} else {
		fmt.Println("Certificate has expired. Run: vsh login")
	}
}

func cmdSSH(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: vsh ssh [user@]host [ssh-options...]")
		os.Exit(1)
	}

	// Check certificate exists and is valid
	homeDir, _ := os.UserHomeDir()
	certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
	keyPath := filepath.Join(homeDir, ".ssh", "id_ed25519")

	if _, err := os.Stat(certPath); err != nil {
		fmt.Println("No SSH certificate found. Run: vsh login")
		os.Exit(1)
	}

	// Build SSH command
	sshArgs := []string{"-i", keyPath}
	sshArgs = append(sshArgs, args...)

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Printf("SSH failed: %v\n", err)
		os.Exit(1)
	}
}

func cmdPubkey() {
	if serverURL == "" {
		fmt.Println("Server not configured. Run: vsh login --server <URL>")
		os.Exit(1)
	}

	// Warn about potential HSTS issues
	if strings.HasPrefix(serverURL, "http://") && strings.Contains(serverURL, ".ts.net") {
		fmt.Println("Note: If this fails, try using the server's IP address instead of .ts.net domain")
	}

	resp, err := http.Get(serverURL + "/pubkey")
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	fmt.Print(string(buf[:n]))
}
