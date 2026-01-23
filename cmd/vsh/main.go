package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	configDir, _ := os.UserConfigDir()
	vshDir = filepath.Join(configDir, "voussh")
	os.MkdirAll(vshDir, 0700)

	// Migrate old config if it exists
	oldVshDir := filepath.Join(homeDir, ".vsh")
	oldConfigPath := filepath.Join(oldVshDir, "config")
	newConfigPath := filepath.Join(vshDir, "current_server")

	if _, err := os.Stat(oldConfigPath); err == nil {
		if data, err := os.ReadFile(oldConfigPath); err == nil {
			os.WriteFile(newConfigPath, data, 0600)
			addServerToHistory(strings.TrimSpace(string(data)))
			os.Remove(oldConfigPath)
		}
	}
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
		configPath := filepath.Join(vshDir, "current_server")
		if data, err := os.ReadFile(configPath); err == nil {
			serverURL = strings.TrimSpace(string(data))
		}
	}

	switch cmd {
	case "init":
		cmdInit()
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
	fmt.Println("  init    Output shell function for local session support")
	fmt.Println("  login   Login and obtain SSH certificate")
	fmt.Println("  logout  Remove SSH certificate and clear config")
	fmt.Println("  status  Show current login status")
	fmt.Println("  ssh     SSH to a host using certificate")
	fmt.Println("  pubkey  Get CA public key from server")
}

func cmdInit() {
	// Output shell function that wraps vsh for local session support
	fmt.Print(`# VSH Shell Function - provides seamless local session support
# Add this to your shell profile with: eval "$(vsh init)"

# Find the vsh binary path
_VSH_BIN="$(which vsh 2>/dev/null || echo vsh)"

# Main vsh function that wraps the binary
vsh() {
    local cmd="$1"

    case "$cmd" in
        login)
            # Check if --local flag is present
            if [[ " ${@:2} " =~ " --local " ]]; then
                # Local login - capture the certificate in environment
                local output
                output=$(VSH_EVAL_MODE=1 "$_VSH_BIN" "$@" 2>&1)
                if [ $? -eq 0 ]; then
                    # Execute the exports in the current shell
                    eval "$output"
                    echo "Local session created successfully!"
                    "$_VSH_BIN" status
                else
                    echo "$output"
                    return 1
                fi
            else
                # Global login - just run the command normally
                "$_VSH_BIN" "$@"
            fi
            ;;
        logout)
            # Check if we have a local session
            if [ -n "$VSH_LOCAL_CERT" ]; then
                # Local logout - unset variables directly
                unset VSH_LOCAL_CERT VSH_LOCAL_SERVER VSH_LOCAL_ROLE
                echo "Local session cleared"
            else
                # Global logout
                "$_VSH_BIN" logout
            fi
            ;;
        *)
            # All other commands pass through
            "$_VSH_BIN" "$@"
            ;;
    esac
}

# Optional: Create an alias for backward compatibility
alias vshl=vsh
`)
}

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "Server URL")
	role := fs.String("role", "", "Role to assume (default: user's default role)")
	local := fs.Bool("local", false, "Create a local session (shell-specific) instead of global")
	fs.Parse(args)

	// If no server specified, use history or prompt
	if *server == "" {
		selectedServer, err := selectServer()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		*server = selectedServer
	}

	serverURL = *server

	// Add to server history
	addServerToHistory(serverURL)

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

		if *local {
			// For local sessions, output environment variables to be sourced
			// This allows the certificate to be stored in the shell's environment
			certB64 := base64.StdEncoding.EncodeToString(certData)

			// Check if we're in eval mode (output is being captured)
			if os.Getenv("VSH_EVAL_MODE") == "1" {
				// Output shell commands to set environment variables
				fmt.Printf("export VSH_LOCAL_CERT='%s'\n", certB64)
				fmt.Printf("export VSH_LOCAL_SERVER='%s'\n", serverURL)
				fmt.Printf("export VSH_LOCAL_ROLE='%s'\n", result.role)
			} else {
				fmt.Printf("Login successful! Role: %s\n", result.role)
				fmt.Println("\nLocal session created. To activate it in your shell, run:")
				roleArg := ""
				if *role != "" {
					roleArg = " --role " + *role
				}
				fmt.Printf("  eval \"$(VSH_EVAL_MODE=1 vsh login --local --server %s%s)\"\n", serverURL, roleArg)
			}
		} else {
			// Global session - write certificate to ~/.ssh/id_ed25519-cert.pub
			certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
			if err := os.WriteFile(certPath, certData, 0644); err != nil {
				fmt.Printf("Failed to save certificate: %v\n", err)
				os.Exit(1)
			}

			// Save current server
			configPath := filepath.Join(vshDir, "current_server")
			os.WriteFile(configPath, []byte(serverURL), 0600)

			fmt.Printf("Login successful! Role: %s\n", result.role)
			fmt.Printf("Certificate saved to: %s (global session)\n", certPath)
		}

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
	// Check if we have a local session
	if os.Getenv("VSH_LOCAL_CERT") != "" {
		// If in eval mode, just output the unset commands
		if len(os.Args) > 2 && os.Args[2] == "--eval" {
			fmt.Print("unset VSH_LOCAL_CERT VSH_LOCAL_SERVER VSH_LOCAL_ROLE")
			return
		}

		// Local session - explain why we can't clear it directly
		fmt.Println("Local session detected.")
		fmt.Println("\nNote: Local sessions are stored in your shell's environment variables.")
		fmt.Println("The vsh command cannot directly modify your shell's environment.")
		fmt.Println("\nTo clear the local session, you have two options:")
		fmt.Println("\n1. Run this command to clear it automatically:")
		fmt.Println("   eval \"$(vsh logout --eval)\"")
		fmt.Println("\n2. Or manually unset the variables:")
		fmt.Println("   unset VSH_LOCAL_CERT VSH_LOCAL_SERVER VSH_LOCAL_ROLE")
		return
	}

	// Global session logout
	homeDir, _ := os.UserHomeDir()
	certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
	configPath := filepath.Join(vshDir, "current_server")

	// Remove certificate
	if err := os.Remove(certPath); err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Failed to remove certificate: %v\n", err)
		}
	} else {
		fmt.Println("Global certificate removed")
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
	var certData []byte
	var sessionType string
	var serverInfo string

	// Check for local session first
	localCert := os.Getenv("VSH_LOCAL_CERT")
	if localCert != "" {
		// Local session
		decoded, err := base64.StdEncoding.DecodeString(localCert)
		if err != nil {
			fmt.Println("Invalid local session. Run: vsh login --local")
			return
		}
		certData = decoded
		sessionType = "Local (shell-specific)"
		serverInfo = os.Getenv("VSH_LOCAL_SERVER")
		if serverInfo != "" {
			serverInfo = " - Server: " + serverInfo
		}
	} else {
		// Global session
		homeDir, _ := os.UserHomeDir()
		certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")

		data, err := os.ReadFile(certPath)
		if err != nil {
			fmt.Println("No SSH certificate found. Run: vsh login")
			return
		}
		certData = data
		sessionType = "Global (all shells)"

		// Get server from config
		configPath := filepath.Join(vshDir, "current_server")
		if serverData, err := os.ReadFile(configPath); err == nil {
			serverInfo = " - Server: " + strings.TrimSpace(string(serverData))
		}
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

	fmt.Printf("Session type: %s%s\n", sessionType, serverInfo)
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

	homeDir, _ := os.UserHomeDir()
	keyPath := filepath.Join(homeDir, ".ssh", "id_ed25519")

	// Check for local session first (environment variable)
	localCert := os.Getenv("VSH_LOCAL_CERT")
	if localCert != "" {
		// Local session exists - use temporary certificate file
		certData, err := base64.StdEncoding.DecodeString(localCert)
		if err != nil {
			fmt.Printf("Failed to decode local certificate: %v\n", err)
			fmt.Println("Run: eval \"$(VSH_EVAL_MODE=1 vsh login --local --server <URL>)\"")
			os.Exit(1)
		}

		// Create temporary certificate file for SSH
		tempFile, err := os.CreateTemp("", "vsh-cert-*.pub")
		if err != nil {
			fmt.Printf("Failed to create temp file: %v\n", err)
			os.Exit(1)
		}
		tempCertPath := tempFile.Name()
		defer os.Remove(tempCertPath)

		if err := os.WriteFile(tempCertPath, certData, 0600); err != nil {
			fmt.Printf("Failed to write temp certificate: %v\n", err)
			os.Exit(1)
		}

		// Build SSH command with temp certificate
		sshArgs := []string{"-i", keyPath, "-o", "CertificateFile=" + tempCertPath}
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
	} else {
		// No local session - check for global certificate
		certPath := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")
		if _, err := os.Stat(certPath); err != nil {
			fmt.Println("No SSH certificate found. Run: vsh login")
			os.Exit(1)
		}

		// Build SSH command with global certificate
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

// addServerToHistory adds a server URL to the history file
func addServerToHistory(serverURL string) {
	historyPath := filepath.Join(vshDir, "server_history")

	// Read existing history
	var servers []string
	if data, err := os.ReadFile(historyPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && line != serverURL {
				servers = append(servers, line)
			}
		}
	}

	// Add current server to the front
	servers = append([]string{serverURL}, servers...)

	// Keep only the last 10 servers
	if len(servers) > 10 {
		servers = servers[:10]
	}

	// Write back to file
	content := strings.Join(servers, "\n")
	os.WriteFile(historyPath, []byte(content), 0600)
}

// getServerHistory returns the list of previously used servers
func getServerHistory() []string {
	historyPath := filepath.Join(vshDir, "server_history")

	data, err := os.ReadFile(historyPath)
	if err != nil {
		return []string{}
	}

	var servers []string
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			servers = append(servers, line)
		}
	}

	return servers
}

// selectServer prompts the user to select a server from history or enter a new one
func selectServer() (string, error) {
	servers := getServerHistory()

	if len(servers) == 0 {
		fmt.Print("Enter server URL: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(input), nil
	}

	if len(servers) == 1 {
		fmt.Printf("Using server: %s\n", servers[0])
		return servers[0], nil
	}

	// Multiple servers - show menu
	fmt.Println("Select a server:")
	for i, server := range servers {
		fmt.Printf("  %d) %s\n", i+1, server)
	}
	fmt.Printf("  %d) Enter new server URL\n", len(servers)+1)

	fmt.Print("Choice [1]: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	choice := strings.TrimSpace(input)
	if choice == "" {
		choice = "1"
	}

	choiceNum, err := strconv.Atoi(choice)
	if err != nil {
		return "", fmt.Errorf("invalid choice: %s", choice)
	}

	if choiceNum >= 1 && choiceNum <= len(servers) {
		return servers[choiceNum-1], nil
	}

	if choiceNum == len(servers)+1 {
		fmt.Print("Enter server URL: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(input), nil
	}

	return "", fmt.Errorf("invalid choice: %d", choiceNum)
}
