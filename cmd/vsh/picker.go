package main

// Running vsh with no arguments opens a picker: recently used `vsh ssh`
// targets first, then the hosts from ~/.ssh/config. Choosing one connects to
// it, logging in first if the certificate is missing or has expired.
//
// The finder is fzf when it is installed, and a plain numbered prompt when it
// is not, so nothing here adds a dependency.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxSSHHistory bounds the remembered targets.
const maxSSHHistory = 50

// errPickCancelled means the user dismissed the picker.
var errPickCancelled = errors.New("cancelled")

func sshHistoryPath() string { return filepath.Join(vshDir, "ssh_history") }

// sshFlagsWithArgument are the ssh options that consume the next argument
// (from ssh(1)); every other single-letter option stands alone.
const sshFlagsWithArgument = "BbcDEeFIiJLlmOoPpQRSWw"

// connectionArgs reduces a `vsh ssh` argument list to the part that says
// where and how to connect: vsh's own -a, ssh's options and the destination.
// A remote command is dropped — `vsh ssh web1 uptime` is remembered as a
// connection to web1, not as a thing to run again. It returns nil when there
// is no destination.
func connectionArgs(args []string) []string {
	var out []string
	haveDestination := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if haveDestination {
				break // the remote command starts here
			}
			haveDestination = true
			out = append(out, arg)
			continue
		}
		out = append(out, arg)
		// For a cluster such as -vp, only an argument-taking letter in last
		// position borrows the next argument; earlier, the rest of the
		// cluster is its value.
		for j := 1; j < len(arg); j++ {
			if strings.IndexByte(sshFlagsWithArgument, arg[j]) < 0 {
				continue
			}
			if j == len(arg)-1 && i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
			break
		}
	}
	if !haveDestination {
		return nil
	}
	return out
}

// displayArgs renders an argument list as one line for the picker.
func displayArgs(args []string) string {
	parts := make([]string, len(args))
	for i, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t'\"\\") {
			arg = strconv.Quote(arg)
		}
		parts[i] = arg
	}
	return strings.Join(parts, " ")
}

// loadSSHHistory returns remembered connections, most recent first.
func loadSSHHistory() [][]string {
	data, err := os.ReadFile(sshHistoryPath())
	if err != nil {
		return nil
	}
	var out [][]string
	for _, line := range strings.Split(string(data), "\n") {
		var args []string
		if json.Unmarshal([]byte(line), &args) == nil && len(args) > 0 {
			out = append(out, args)
		}
	}
	return out
}

// recordSSHTarget moves a connection to the front of the history.
func recordSSHTarget(args []string) {
	conn := connectionArgs(args)
	if conn == nil {
		return
	}
	key := displayArgs(conn)
	entries := [][]string{conn}
	for _, old := range loadSSHHistory() {
		if displayArgs(old) != key && len(entries) < maxSSHHistory {
			entries = append(entries, old)
		}
	}
	var b strings.Builder
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			return
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	// History is a convenience: failing to write it must not fail the
	// connection that is about to be made.
	if os.MkdirAll(vshDir, 0700) == nil {
		writeFileAtomic(sshHistoryPath(), []byte(b.String()), 0600)
	}
}

// sshConfigHosts lists the concrete host aliases in an ssh config file,
// following Include directives. Patterns (*, ?, !) are not hosts one can
// connect to and are skipped.
func sshConfigHosts(path string) []string {
	seen := map[string]bool{}
	var hosts []string
	readSSHConfig(path, filepath.Dir(path), 0, func(host string) {
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	})
	return hosts
}

func readSSHConfig(path, baseDir string, depth int, add func(string)) {
	if depth > 4 {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "Keyword value" and "Keyword=value" are both legal.
		line = strings.Replace(line, "=", " ", 1)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			for _, name := range fields[1:] {
				name = strings.Trim(name, `"`)
				if name != "" && !strings.ContainsAny(name, "*?!") {
					add(name)
				}
			}
		case "include":
			for _, pattern := range fields[1:] {
				pattern = strings.Trim(pattern, `"`)
				if strings.HasPrefix(pattern, "~/") {
					if home, err := os.UserHomeDir(); err == nil {
						pattern = filepath.Join(home, pattern[2:])
					}
				} else if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(baseDir, pattern)
				}
				matches, _ := filepath.Glob(pattern)
				for _, match := range matches {
					readSSHConfig(match, baseDir, depth+1, add)
				}
			}
		}
	}
}

// pickerEntry is one line of the picker and what choosing it runs.
type pickerEntry struct {
	label string
	args  []string
}

// sshCandidates builds the picker's list: recent connections, then config
// hosts that are not already there as a plain recent destination.
func sshCandidates() []pickerEntry {
	var entries []pickerEntry
	seen := map[string]bool{}
	for _, args := range loadSSHHistory() {
		label := displayArgs(args)
		if !seen[label] {
			seen[label] = true
			entries = append(entries, pickerEntry{label: label, args: args})
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, host := range sshConfigHosts(filepath.Join(home, ".ssh", "config")) {
			if !seen[host] {
				seen[host] = true
				entries = append(entries, pickerEntry{label: host, args: []string{host}})
			}
		}
	}
	return entries
}

// isTerminal reports whether f looks like an interactive terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// findFzf locates the fzf binary; "" means use the built-in prompt. It is a
// variable so tests can pretend either way.
var findFzf = func() string {
	path, err := exec.LookPath("fzf")
	if err != nil {
		return ""
	}
	return path
}

// pickOne asks the user to choose one of items, or to type something that is
// not in the list. It returns errPickCancelled if they back out.
func pickOne(items []string, prompt, header string) (string, error) {
	if fzf := findFzf(); fzf != "" && len(items) > 0 {
		return pickWithFzf(fzf, items, prompt, header)
	}
	return pickNumbered(items, prompt, os.Stdin, os.Stderr)
}

// pickWithFzf runs fzf over items. --print-query makes fzf report what was
// typed as well as what was selected, so text matching nothing in the list
// can be taken as a new entry.
func pickWithFzf(fzf string, items []string, prompt, header string) (string, error) {
	// Layout is left to fzf's defaults and the user's own FZF_DEFAULT_OPTS;
	// only what the selection logic depends on is set here.
	cmd := exec.Command(fzf, "--prompt", prompt, "--header", header, "--no-multi", "--print-query")
	cmd.Stdin = strings.NewReader(strings.Join(items, "\n") + "\n")
	cmd.Stderr = os.Stderr // fzf draws its interface here
	out, err := cmd.Output()

	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		return "", fmt.Errorf("failed to run fzf: %w", err)
	}
	return parseFzfOutput(string(out), code)
}

// parseFzfOutput interprets fzf's --print-query output: the query on the
// first line, the selection (if any) on the second. Exit status 0 is a
// selection, 1 is "nothing matched", 130 is Esc or Ctrl-C.
func parseFzfOutput(out string, code int) (string, error) {
	if code != 0 && code != 1 {
		return "", errPickCancelled
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
		return lines[1], nil
	}
	if query := strings.TrimSpace(lines[0]); query != "" {
		return query, nil
	}
	return "", errPickCancelled
}

// maxNumbered is how many entries the fallback prompt lists.
const maxNumbered = 20

// pickNumbered is the finder for machines without fzf: a numbered list, and
// a prompt that accepts a number or free text.
func pickNumbered(items []string, prompt string, in io.Reader, out io.Writer) (string, error) {
	shown := items
	if len(shown) > maxNumbered {
		shown = shown[:maxNumbered]
	}
	for i, item := range shown {
		fmt.Fprintf(out, "  %2d) %s\n", i+1, item)
	}
	if len(items) > len(shown) {
		fmt.Fprintf(out, "      ... and %d more (install fzf to search them all)\n", len(items)-len(shown))
	}
	if len(shown) > 0 {
		fmt.Fprintf(out, "%s[1] ", prompt)
	} else {
		fmt.Fprint(out, prompt)
	}

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return "", errPickCancelled
	}
	answer := strings.TrimSpace(line)
	if answer == "" {
		if len(shown) == 0 {
			return "", errPickCancelled
		}
		return shown[0], nil
	}
	if n, err := strconv.Atoi(answer); err == nil {
		if n < 1 || n > len(shown) {
			return "", fmt.Errorf("invalid choice: %d", n)
		}
		return shown[n-1], nil
	}
	return answer, nil
}

// cmdPick is bare `vsh`: choose a host, make sure there is a usable
// certificate, connect.
func cmdPick() {
	entries := sshCandidates()
	labels := make([]string, len(entries))
	byLabel := make(map[string][]string, len(entries))
	for i, entry := range entries {
		labels[i] = entry.label
		byLabel[entry.label] = entry.args
	}

	choice, err := pickOne(labels, "vsh ssh> ", "Enter: connect · or type a new [user@]host")
	if errors.Is(err, errPickCancelled) {
		return
	}
	if err != nil {
		fatalf("%v", err)
	}
	args, known := byLabel[choice]
	if !known {
		// Something typed rather than picked: a new destination, possibly
		// with options, exactly as it would follow `vsh ssh`.
		args = strings.Fields(choice)
	}
	if connectionArgs(args) == nil {
		fatalf("no host given")
	}

	ensureSession()
	cmdSSH(args)
}

// certificateStatus describes the certificate a connection would use.
type certificateStatus struct {
	local   bool             // held in $VSH_LOCAL_CERT rather than on disk
	cert    *ssh.Certificate // nil when there is none (or it does not parse)
	expires time.Time
}

// loginMargin is how much validity a certificate must have left to be used
// without logging in again: enough to complete the connection.
const loginMargin = 30 * time.Second

func (s certificateStatus) needsLogin(now time.Time) bool {
	return s.cert == nil || !now.Add(loginMargin).Before(s.expires)
}

// currentCertificate loads the certificate `vsh ssh` would present: the
// shell-local one if the shell has one, otherwise the global one on disk.
func currentCertificate() certificateStatus {
	var status certificateStatus
	var data []byte
	if encoded := os.Getenv("VSH_LOCAL_CERT"); encoded != "" {
		status.local = true
		data, _ = base64.StdEncoding.DecodeString(encoded)
	} else if home, err := os.UserHomeDir(); err == nil {
		data, _ = os.ReadFile(filepath.Join(home, ".ssh", "id_ed25519-cert.pub"))
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return status
	}
	if cert, ok := parsed.(*ssh.Certificate); ok {
		status.cert = cert
		status.expires = time.Unix(int64(cert.ValidBefore), 0)
	}
	return status
}

// loginArgs builds the `vsh login` invocation that renews a certificate: the
// same role as the one being replaced, and the device flow when this is a
// remote shell with no browser of its own.
func loginArgs(status certificateStatus) []string {
	var args []string
	if status.cert != nil {
		if _, role := splitKeyID(status.cert.KeyId); role != "" {
			args = append(args, "--role", role)
		}
	}
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		args = append(args, "--device")
	}
	return args
}

// ensureSession logs in if the certificate is missing or expired, so the
// connection that follows does not fail on a stale credential.
func ensureSession() {
	status := currentCertificate()
	if !status.needsLogin(time.Now()) {
		return
	}
	if status.local {
		// A shell-local certificate lives in the parent shell's environment,
		// which this process cannot rewrite.
		fatalf("Your local session has expired. Run: vsh login --local")
	}
	if status.cert == nil {
		fmt.Fprintln(os.Stderr, "No certificate yet — logging in first.")
	} else {
		fmt.Fprintf(os.Stderr, "Certificate expired at %s — logging in first.\n", status.expires.Format("15:04 on Jan 2"))
	}
	runLogin(loginArgs(status)) // exits on failure
	fmt.Fprintln(os.Stderr)
}

// runLogin performs the login. It is a variable so tests can observe the
// decision without a browser.
var runLogin = cmdLogin
