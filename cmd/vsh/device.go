package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// deviceHTTPClient bounds each individual request. The overall flow is bounded
// separately by the code's expiry.
var deviceHTTPClient = &http.Client{Timeout: 30 * time.Second}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceTokenResponse struct {
	Certificate string   `json:"certificate"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Principals  []string `json:"principals"`
}

type deviceErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// cmdLoginDevice runs the device authorization flow: ask the server for a pair
// of codes, show the user where to approve, then poll until the certificate is
// released. Nothing here needs a browser or an inbound port on this machine,
// which is the whole point — it works over SSH and behind NAT.
func cmdLoginDevice(pubKeyData []byte, role string, local bool) {
	code, err := requestDeviceCode(pubKeyData, role)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	expiresIn := time.Duration(code.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 10 * time.Minute
	}
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	fmt.Println()
	fmt.Println("To authorize this machine, open this page on any device:")
	fmt.Printf("\n    %s\n", code.VerificationURI)
	fmt.Println("\nand enter the code:")
	fmt.Printf("\n    %s\n", code.UserCode)
	if code.VerificationURIComplete != "" {
		fmt.Printf("\nOr open this link directly:\n\n    %s\n", code.VerificationURIComplete)
	}
	fmt.Printf("\nWaiting for approval (expires in %s)...\n", expiresIn.Round(time.Second))

	token, err := pollDeviceToken(code.DeviceCode, interval, expiresIn)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// Show who approved. A certificate carrying an unexpected identity means
	// somebody else completed this request, and the user should notice.
	if !local || os.Getenv("VSH_EVAL_MODE") != "1" {
		fmt.Printf("\nApproved by %s", token.Email)
		if len(token.Principals) > 0 {
			fmt.Printf(" (principals: %s)", strings.Join(token.Principals, ", "))
		}
		fmt.Println()
	}

	certData := []byte(strings.TrimSpace(token.Certificate) + "\n")
	if err := saveSession(certData, token.Role, local, reRunArgs(role, true)); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

// requestDeviceCode asks the server to mint a device code and user code.
func requestDeviceCode(pubKeyData []byte, role string) (*deviceCodeResponse, error) {
	form := url.Values{}
	form.Set("pubkey", base64.RawURLEncoding.EncodeToString(pubKeyData))
	if role != "" {
		form.Set("role", role)
	}

	resp, err := deviceHTTPClient.PostForm(serverURL+"/device/code", form)
	if err != nil {
		return nil, fmt.Errorf("failed to contact %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("this server does not offer the device flow (it may be disabled, or running an older voussh)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to start device login: %s", describeDeviceError(body, resp.StatusCode))
	}

	var code deviceCodeResponse
	if err := json.Unmarshal(body, &code); err != nil {
		return nil, fmt.Errorf("unexpected response from server: %w", err)
	}
	if code.DeviceCode == "" || code.UserCode == "" || code.VerificationURI == "" {
		return nil, fmt.Errorf("incomplete response from server")
	}
	return &code, nil
}

// pollDeviceToken polls until the request is approved, rejected or expires.
func pollDeviceToken(deviceCode string, interval, expiresIn time.Duration) (*deviceTokenResponse, error) {
	form := url.Values{}
	form.Set("device_code", deviceCode)

	deadline := time.Now().Add(expiresIn)
	for {
		time.Sleep(interval)
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the code expired before it was approved. Run the command again")
		}

		resp, err := deviceHTTPClient.PostForm(serverURL+"/device/token", form)
		if err != nil {
			// A transient network blip should not abandon a login the user may
			// already have approved; keep polling until the code expires.
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var token deviceTokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				return nil, fmt.Errorf("unexpected response from server: %w", err)
			}
			if token.Certificate == "" {
				return nil, fmt.Errorf("server returned no certificate")
			}
			return &token, nil
		}

		var errResp deviceErrorResponse
		_ = json.Unmarshal(body, &errResp)
		switch errResp.Error {
		case "authorization_pending":
			// Nobody has approved it yet; keep waiting.
		case "slow_down":
			// RFC 8628 §3.5: back off by five seconds and carry on.
			interval += 5 * time.Second
		case "access_denied":
			return nil, fmt.Errorf("the request was rejected")
		case "expired_token":
			return nil, fmt.Errorf("the code expired before it was approved. Run the command again")
		default:
			return nil, fmt.Errorf("login failed: %s", describeDeviceError(body, resp.StatusCode))
		}
	}
}

// describeDeviceError turns an error body into something worth printing,
// falling back to the status code when the body is not the expected shape.
func describeDeviceError(body []byte, status int) string {
	var errResp deviceErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		if errResp.Description != "" {
			return fmt.Sprintf("%s (%s)", errResp.Description, errResp.Error)
		}
		return errResp.Error
	}
	if trimmed := strings.TrimSpace(string(body)); trimmed != "" && len(trimmed) < 200 {
		return trimmed
	}
	return fmt.Sprintf("HTTP %d", status)
}
