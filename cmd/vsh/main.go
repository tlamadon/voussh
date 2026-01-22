package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"
)

var (
	serverURL string
	vshDir    string
)

type Target struct {
	Host        string   `yaml:"host"`
	User        string   `yaml:"user"`
	Port        int      `yaml:"port"`
	Groups      []string `yaml:"groups"`
	Description string   `yaml:"description"`
	ProxyCommand string  `yaml:"proxy_command,omitempty"`
}

type TargetsConfig struct {
	Targets map[string]Target `yaml:"targets"`
}

func init() {
	homeDir, _ := os.UserHomeDir()
	vshDir = filepath.Join(homeDir, ".vsh")
	os.MkdirAll(vshDir, 0700)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: vsh <command> [options]")
		fmt.Println("Commands: login, sign, pubkey, status, ssh")
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

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
	case "sign":
		cmdSign(args)
	case "pubkey":
		cmdPubkey()
	case "status":
		cmdStatus()
	case "ssh":
		cmdSSH(args)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", serverURL, "Server URL")
	fs.Parse(args)

	if *server == "" {
		fmt.Println("Server URL required (use --server or VSH_SERVER env)")
		os.Exit(1)
	}
	serverURL = *server

	loginURL := serverURL + "/login"
	fmt.Printf("Opening browser to: %s\n", loginURL)
	exec.Command("open", loginURL).Run()

	fmt.Print("Enter token from browser: ")
	var token string
	fmt.Scanln(&token)

	tokenPath := filepath.Join(vshDir, "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		fmt.Printf("Failed to save token: %v\n", err)
		os.Exit(1)
	}

	configPath := filepath.Join(vshDir, "config")
	if err := os.WriteFile(configPath, []byte(serverURL), 0600); err != nil {
		fmt.Printf("Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Login successful!")
}

func cmdSign(args []string) {
	if serverURL == "" {
		fmt.Println("Not logged in. Run: vsh login")
		os.Exit(1)
	}

	homeDir, _ := os.UserHomeDir()
	keyFile := filepath.Join(homeDir, ".ssh", "id_ed25519.pub")
	if len(args) > 0 {
		keyFile = args[0]
	}

	pubKeyData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	tokenPath := filepath.Join(vshDir, "token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Println("Not logged in. Run: vsh login")
		os.Exit(1)
	}

	reqBody, _ := json.Marshal(map[string]string{
		"public_key": string(pubKeyData),
	})

	req, _ := http.NewRequest("POST", serverURL+"/sign", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Sign failed: %s\n", string(body))
		os.Exit(1)
	}

	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if err := os.WriteFile(certFile, body, 0644); err != nil {
		fmt.Printf("Failed to write certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate written to: %s\n", certFile)
}

func cmdPubkey() {
	if serverURL == "" {
		fmt.Println("Not logged in. Run: vsh login")
		os.Exit(1)
	}

	resp, err := http.Get(serverURL + "/pubkey")
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Print(string(body))
}

func cmdStatus() {
	tokenPath := filepath.Join(vshDir, "token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Println("Not logged in")
		return
	}

	verifier := &oidc.IDTokenVerifier{}
	parsedToken, _ := verifier.Verify(nil, string(token))

	if parsedToken != nil {
		var claims struct {
			Email string `json:"email"`
			Exp   int64  `json:"exp"`
		}
		parsedToken.Claims(&claims)

		if claims.Email != "" {
			fmt.Printf("Logged in as %s\n", claims.Email)
			if claims.Exp > 0 {
				expiry := time.Unix(claims.Exp, 0)
				remaining := time.Until(expiry)
				if remaining > 0 {
					fmt.Printf("Token expires in %v\n", remaining.Round(time.Minute))
				} else {
					fmt.Println("Token has expired")
				}
			}
		}
	} else {
		tokenStr := string(token)
		parts := strings.Split(tokenStr, ".")
		if len(parts) == 3 {
			payload := parts[1]
			if len(payload)%4 != 0 {
				payload += strings.Repeat("=", 4-len(payload)%4)
			}
			decoded, _ := base64URLDecode(payload)
			var claims map[string]interface{}
			if json.Unmarshal(decoded, &claims) == nil {
				if email, ok := claims["email"].(string); ok {
					fmt.Printf("Logged in as %s\n", email)
				}
				if exp, ok := claims["exp"].(float64); ok {
					expiry := time.Unix(int64(exp), 0)
					remaining := time.Until(expiry)
					if remaining > 0 {
						fmt.Printf("Token expires in %v\n", remaining.Round(time.Minute))
					} else {
						fmt.Println("Token has expired")
					}
				}
			}
		}
	}
}

func base64URLDecode(s string) ([]byte, error) {
	b := []byte(s)
	for i := range b {
		switch b[i] {
		case '-':
			b[i] = '+'
		case '_':
			b[i] = '/'
		}
	}
	dst := make([]byte, len(b))
	n, err := base64.StdEncoding.Decode(dst, b)
	return dst[:n], err
}

var base64 = struct {
	StdEncoding *base64Encoding
}{
	StdEncoding: &base64Encoding{},
}

type base64Encoding struct{}

func (e *base64Encoding) Decode(dst, src []byte) (n int, err error) {
	var val uint32
	var valb int
	di := 0

	for _, b := range src {
		var c byte
		switch {
		case b >= 'A' && b <= 'Z':
			c = b - 'A'
		case b >= 'a' && b <= 'z':
			c = b - 'a' + 26
		case b >= '0' && b <= '9':
			c = b - '0' + 52
		case b == '+':
			c = 62
		case b == '/':
			c = 63
		case b == '=':
			continue
		default:
			continue
		}

		val = (val << 6) | uint32(c)
		valb += 6

		for valb >= 8 {
			valb -= 8
			if di < len(dst) {
				dst[di] = byte(val >> uint(valb))
				di++
			}
		}
	}

	return di, nil
}

func cmdSSH(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: vsh ssh <target>")
		fmt.Println("\nAvailable targets:")
		listTargets()
		os.Exit(1)
	}

	targetName := args[0]
	sshArgs := args[1:]

	targets, err := loadTargets()
	if err != nil {
		fmt.Printf("Failed to load targets: %v\n", err)
		os.Exit(1)
	}

	target, exists := targets.Targets[targetName]
	if !exists {
		fmt.Printf("Unknown target: %s\n", targetName)
		fmt.Println("\nAvailable targets:")
		listTargets()
		os.Exit(1)
	}

	if !hasAccessToTarget(target) {
		fmt.Printf("Access denied: you don't have permission to access %s\n", targetName)
		os.Exit(1)
	}

	ensureCertificate()

	sshCommand := buildSSHCommand(target, sshArgs)
	cmd := exec.Command("ssh", sshCommand...)
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

func loadTargets() (*TargetsConfig, error) {
	targetsFile := os.Getenv("VSH_TARGETS")
	if targetsFile == "" {
		targetsFile = "targets.yaml"
	}

	data, err := os.ReadFile(targetsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets file: %w", err)
	}

	var config TargetsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse targets file: %w", err)
	}

	return &config, nil
}

func listTargets() {
	targets, err := loadTargets()
	if err != nil {
		return
	}

	userGroups := getUserGroups()

	for name, target := range targets.Targets {
		if hasAccessToTargetWithGroups(target, userGroups) {
			fmt.Printf("  %-20s %s@%s:%d - %s\n",
				name, target.User, target.Host, target.Port, target.Description)
		}
	}
}

func hasAccessToTarget(target Target) bool {
	userGroups := getUserGroups()
	return hasAccessToTargetWithGroups(target, userGroups)
}

func hasAccessToTargetWithGroups(target Target, userGroups []string) bool {
	if len(target.Groups) == 0 {
		return true
	}

	for _, targetGroup := range target.Groups {
		for _, userGroup := range userGroups {
			if targetGroup == userGroup {
				return true
			}
		}
	}

	return false
}

func getUserGroups() []string {
	groupsFile := filepath.Join(vshDir, "groups")

	if data, err := os.ReadFile(groupsFile); err == nil {
		var userInfo struct {
			Groups []string `json:"groups"`
			Expiry time.Time `json:"expiry"`
		}
		if json.Unmarshal(data, &userInfo) == nil {
			if time.Now().Before(userInfo.Expiry) {
				return userInfo.Groups
			}
		}
	}

	if serverURL == "" {
		return nil
	}

	tokenPath := filepath.Join(vshDir, "token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil
	}

	req, _ := http.NewRequest("GET", serverURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var userInfo struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil
	}

	cacheData := struct {
		Groups []string  `json:"groups"`
		Expiry time.Time `json:"expiry"`
	}{
		Groups: userInfo.Groups,
		Expiry: time.Now().Add(1 * time.Hour),
	}

	if cacheJSON, err := json.Marshal(cacheData); err == nil {
		os.WriteFile(groupsFile, cacheJSON, 0600)
	}

	return userInfo.Groups
}

func ensureCertificate() {
	homeDir, _ := os.UserHomeDir()
	certFile := filepath.Join(homeDir, ".ssh", "id_ed25519-cert.pub")

	if _, err := os.Stat(certFile); err != nil {
		fmt.Println("SSH certificate not found. Signing your SSH key...")
		cmdSign([]string{})
	}
}

func buildSSHCommand(target Target, extraArgs []string) []string {
	var args []string

	args = append(args, "-p", fmt.Sprintf("%d", target.Port))

	if target.ProxyCommand != "" && target.ProxyCommand != "none" {
		args = append(args, "-o", fmt.Sprintf("ProxyCommand=%s", target.ProxyCommand))
	}

	args = append(args, fmt.Sprintf("%s@%s", target.User, target.Host))

	args = append(args, extraArgs...)

	return args
}