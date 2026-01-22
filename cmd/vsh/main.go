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
		fmt.Println("Usage: vsh <command> [options]")
		fmt.Println("Commands: login, sign, pubkey, status")
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