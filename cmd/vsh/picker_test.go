package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// useTempHome points both vsh's state and $HOME at scratch directories, and
// clears the environment the code under test reads.
func useTempHome(t *testing.T) string {
	t.Helper()
	useTempConfigDir(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VSH_SERVER", "")
	t.Setenv("VSH_LOCAL_CERT", "")
	t.Setenv("VSH_EVAL_MODE", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	return home
}

// ---------------------------------------------------------------------------
// The saved server
// ---------------------------------------------------------------------------

// failIfAsked makes any prompt for a server a test failure.
func failIfAsked(t *testing.T) {
	t.Helper()
	old := chooseServer
	chooseServer = func() (string, error) {
		t.Error("the user was asked for a server")
		return "", errors.New("unexpected prompt")
	}
	t.Cleanup(func() { chooseServer = old })
}

func TestResolveServerPrecedence(t *testing.T) {
	useTempHome(t)
	failIfAsked(t)
	if err := saveDefaultServer("https://saved.example.com/"); err != nil {
		t.Fatal(err)
	}

	resolve := func(explicit string) string {
		t.Helper()
		got, err := resolveServer(explicit, true)
		if err != nil {
			t.Fatalf("resolveServer(%q): %v", explicit, err)
		}
		return got
	}

	// The saved server is used without a question, trailing slash removed.
	if got := resolve(""); got != "https://saved.example.com" {
		t.Errorf("saved server = %q", got)
	}
	// The environment overrides it...
	t.Setenv("VSH_SERVER", "https://env.example.com")
	if got := resolve(""); got != "https://env.example.com" {
		t.Errorf("with VSH_SERVER = %q", got)
	}
	// ...and --server overrides both, for this invocation only.
	if got := resolve("https://flag.example.com/"); got != "https://flag.example.com" {
		t.Errorf("with --server = %q", got)
	}
	if saved := loadDefaultServer(); saved != "https://saved.example.com" {
		t.Errorf("a one-off --server changed the saved server to %q", saved)
	}
}

// The reported problem: with several servers in the history, every login
// asked which one to use. Now the question is asked once.
func TestResolveServerAsksOnceThenSticks(t *testing.T) {
	useTempHome(t)
	addServerToHistory("https://one.example.com")
	addServerToHistory("https://two.example.com")

	asked := 0
	old := chooseServer
	chooseServer = func() (string, error) {
		asked++
		return "https://one.example.com", nil
	}
	defer func() { chooseServer = old }()

	for i := 0; i < 3; i++ {
		got, err := resolveServer("", true)
		if err != nil || got != "https://one.example.com" {
			t.Fatalf("call %d: %q, %v", i, got, err)
		}
	}
	if asked != 1 {
		t.Errorf("the user was asked %d times, want once", asked)
	}
	if saved := loadDefaultServer(); saved != "https://one.example.com" {
		t.Errorf("saved server = %q", saved)
	}
}

func TestResolveServerWithoutASavedChoice(t *testing.T) {
	// Upgrading with a single server in the history: nothing to ask.
	t.Run("single history entry is adopted", func(t *testing.T) {
		useTempHome(t)
		failIfAsked(t)
		addServerToHistory("https://only.example.com")
		got, err := resolveServer("", true)
		if err != nil || got != "https://only.example.com" {
			t.Fatalf("resolveServer = %q, %v", got, err)
		}
		if loadDefaultServer() != "https://only.example.com" {
			t.Error("the adopted server was not saved")
		}
	})

	// The first server ever named is the one to keep.
	t.Run("first explicit server is saved", func(t *testing.T) {
		useTempHome(t)
		failIfAsked(t)
		if _, err := resolveServer("https://first.example.com", true); err != nil {
			t.Fatal(err)
		}
		if loadDefaultServer() != "https://first.example.com" {
			t.Error("the first explicit server was not saved")
		}
		if got, _ := resolveServer("", true); got != "https://first.example.com" {
			t.Errorf("next call = %q", got)
		}
	})

	// A machine with $VSH_SERVER set has made its choice in the environment;
	// nothing is written on its behalf.
	t.Run("environment is not copied to disk", func(t *testing.T) {
		useTempHome(t)
		failIfAsked(t)
		t.Setenv("VSH_SERVER", "https://env.example.com")
		if _, err := resolveServer("https://flag.example.com", true); err != nil {
			t.Fatal(err)
		}
		if saved := loadDefaultServer(); saved != "" {
			t.Errorf("saved server = %q, want none", saved)
		}
	})

	t.Run("non-interactive never prompts", func(t *testing.T) {
		useTempHome(t)
		failIfAsked(t)
		addServerToHistory("https://one.example.com")
		addServerToHistory("https://two.example.com")
		if _, err := resolveServer("", false); err == nil {
			t.Error("resolveServer succeeded with nothing configured")
		}
	})

	t.Run("an empty answer is not saved", func(t *testing.T) {
		useTempHome(t)
		old := chooseServer
		chooseServer = func() (string, error) { return "  ", nil }
		defer func() { chooseServer = old }()
		if _, err := resolveServer("", true); err == nil {
			t.Error("an empty server was accepted")
		}
		if loadDefaultServer() != "" {
			t.Error("an empty server was saved")
		}
	})
}

// Starting vsh must leave nothing behind: not even an empty config directory.
func TestStartupCreatesNothing(t *testing.T) {
	useTempConfigDir(t) // restores vshDir afterwards
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	setupConfigDir()
	if vshDir != filepath.Join(home, ".config", "voussh") {
		t.Skipf("config directory resolves to %s on this platform", vshDir)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("startup created %s", entries[0].Name())
	}

	// The one thing startup may write: an old ~/.vsh/config, carried over.
	if err := os.MkdirAll(filepath.Join(home, ".vsh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vsh", "config"), []byte("https://old.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupConfigDir()
	if data, err := os.ReadFile(filepath.Join(vshDir, "current_server")); err != nil || strings.TrimSpace(string(data)) != "https://old.example.com" {
		t.Errorf("old config was not migrated: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".vsh", "config")); !os.IsNotExist(err) {
		t.Error("old config file was left in place")
	}
}

// vsh no longer creates its config directory at startup, so everything that
// writes there has to be able to create it.
func TestWritersCreateTheConfigDirectory(t *testing.T) {
	home := useTempHome(t)
	writers := map[string]func(){
		"server history": func() { addServerToHistory("https://ca.example.com") },
		"default server": func() { saveDefaultServer("https://ca.example.com") },
		"ssh history":    func() { recordSSHTarget([]string{"web1"}) },
		"token": func() {
			saveToken(&tokenRecord{Audience: testAudience, ExpiresAt: time.Now().Add(time.Minute), AccessToken: "t"})
		},
		"http key": func() { ensureHTTPKey(defaultHTTPKeyPath()) },
		"global session": func() {
			installCert(t, home, "alice@example.com@default", time.Hour)
			cert, _ := os.ReadFile(filepath.Join(home, ".ssh", "id_ed25519-cert.pub"))
			saveSession(cert, "default", false, "")
		},
	}
	for name, write := range writers {
		vshDir = filepath.Join(t.TempDir(), "not", "yet", "there")
		write()
		entries, err := os.ReadDir(vshDir)
		if err != nil || len(entries) == 0 {
			t.Errorf("%s: nothing was written (%v)", name, err)
			continue
		}
		if info, err := os.Stat(vshDir); err != nil || info.Mode().Perm() != 0700 {
			t.Errorf("%s: config directory mode = %v, want 700", name, info.Mode().Perm())
		}
	}
}

// ---------------------------------------------------------------------------
// What gets remembered about a connection
// ---------------------------------------------------------------------------

func TestConnectionArgs(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"web1", "web1"},
		{"root@web1", "root@web1"},
		{"-a root@web1", "-a root@web1"},
		{"-p 2222 web1", "-p 2222 web1"},
		{"web1 -p 2222", "web1 -p 2222"},
		{"-p2222 web1", "-p2222 web1"},
		{"-vp 2222 web1", "-vp 2222 web1"},
		{"-J bastion -L 8080:localhost:80 web1", "-J bastion -L 8080:localhost:80 web1"},
		{"-o StrictHostKeyChecking=no web1", "-o StrictHostKeyChecking=no web1"},
		// A remote command is not part of where to connect.
		{"web1 uptime", "web1"},
		{"web1 ls -la /tmp", "web1"},
		{"-t web1 sudo journalctl -f", "-t web1"},
		{"web1 -- ls", "web1"},
		// No destination, nothing to remember.
		{"", ""},
		{"-v", ""},
		{"-p 2222", ""},
	}
	for _, tc := range cases {
		got := strings.Join(connectionArgs(strings.Fields(tc.in)), " ")
		if got != tc.want {
			t.Errorf("connectionArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSSHHistory(t *testing.T) {
	useTempHome(t)

	recordSSHTarget([]string{"web1"})
	recordSSHTarget([]string{"-p", "2222", "root@db1"})
	recordSSHTarget([]string{"web1", "uptime"}) // the same connection as the first
	recordSSHTarget([]string{"-v"})             // no destination: ignored

	got := loadSSHHistory()
	want := [][]string{{"web1"}, {"-p", "2222", "root@db1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("history = %v, want %v (most recent first, no duplicates)", got, want)
	}

	// An argument with a space survives the round trip intact.
	recordSSHTarget([]string{"-o", "ProxyCommand=ssh -W %h:%p bastion", "web2"})
	if first := loadSSHHistory()[0]; !reflect.DeepEqual(first, []string{"-o", "ProxyCommand=ssh -W %h:%p bastion", "web2"}) {
		t.Errorf("round trip = %q", first)
	}

	for i := 0; i < maxSSHHistory+10; i++ {
		recordSSHTarget([]string{fmt.Sprintf("host%d", i)})
	}
	history := loadSSHHistory()
	if len(history) != maxSSHHistory {
		t.Errorf("history holds %d entries, want it capped at %d", len(history), maxSSHHistory)
	}
	if history[0][0] != fmt.Sprintf("host%d", maxSSHHistory+9) {
		t.Errorf("most recent entry = %v", history[0])
	}
	info, err := os.Stat(sshHistoryPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("history file mode = %v, %v; want 600", info.Mode().Perm(), err)
	}
}

func TestSSHConfigHosts(t *testing.T) {
	home := useTempHome(t)
	sshDir := filepath.Join(home, ".ssh")
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(sshDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("config", `# personal hosts
Host web1 web2
    HostName 10.0.0.1
host db1
Host=cache1
Host "quoted"
Host *.internal !bastion.internal jump?
Host *
    ServerAliveInterval 30
Include conf.d/*.conf
Include missing-file
Host web1
`)
	// As in ssh_config(5), a relative Include is relative to ~/.ssh, wherever
	// the including file itself lives.
	write("conf.d/work.conf", "Host work1\nInclude loop.conf\n")
	write("conf.d/ignored.txt", "Host not-included\n")
	// A file that includes itself must not hang the parser.
	write("loop.conf", "Host looped\nInclude loop.conf\n")

	got := sshConfigHosts(filepath.Join(sshDir, "config"))
	want := []string{"web1", "web2", "db1", "cache1", "quoted", "work1", "looped"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}

	if hosts := sshConfigHosts(filepath.Join(sshDir, "absent")); len(hosts) != 0 {
		t.Errorf("a missing config yielded %v", hosts)
	}
}

func TestSSHCandidates(t *testing.T) {
	home := useTempHome(t)
	config := "Host web1\nHost db1\nHost cache1\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	recordSSHTarget([]string{"db1"})
	recordSSHTarget([]string{"-p", "2222", "root@elsewhere"})

	var labels []string
	for _, entry := range sshCandidates() {
		labels = append(labels, entry.label)
	}
	// Recent connections first, most recent on top; then the config hosts not
	// already listed.
	want := []string{"-p 2222 root@elsewhere", "db1", "web1", "cache1"}
	if !reflect.DeepEqual(labels, want) {
		t.Errorf("candidates = %v, want %v", labels, want)
	}
	// The label is for reading; what runs is the original argument list.
	if args := sshCandidates()[0].args; !reflect.DeepEqual(args, []string{"-p", "2222", "root@elsewhere"}) {
		t.Errorf("args = %q", args)
	}
}

// ---------------------------------------------------------------------------
// The finder
// ---------------------------------------------------------------------------

func TestParseFzfOutput(t *testing.T) {
	cases := []struct {
		name string
		out  string
		code int
		want string // "" means cancelled
	}{
		{"selection", "we\nweb1\n", 0, "web1"},
		{"selection with empty query", "\nweb1\n", 0, "web1"},
		// Nothing matched: what was typed is a new entry.
		{"typed a new host", "root@newhost\n", 1, "root@newhost"},
		{"enter on an empty list", "\n", 1, ""},
		{"escape", "we\n", 130, ""},
		{"fzf error", "", 2, ""},
	}
	for _, tc := range cases {
		got, err := parseFzfOutput(tc.out, tc.code)
		if tc.want == "" {
			if !errors.Is(err, errPickCancelled) {
				t.Errorf("%s: = %q, %v; want cancelled", tc.name, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// fakeFzf writes a stand-in fzf that records its stdin and answers as told.
func fakeFzf(t *testing.T, output string, exitCode int) (path, stdinFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	stdinFile = filepath.Join(dir, "stdin")
	answer := filepath.Join(dir, "answer")
	if err := os.WriteFile(answer, []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "fzf")
	script := fmt.Sprintf("#!/bin/sh\ncat > %q\ncat %q\nexit %d\n", stdinFile, answer, exitCode)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path, stdinFile
}

func TestPickWithFzf(t *testing.T) {
	path, stdinFile := fakeFzf(t, "db\ndb1\n", 0)
	got, err := pickWithFzf(path, []string{"web1", "db1"}, "vsh> ", "header")
	if err != nil || got != "db1" {
		t.Fatalf("pickWithFzf = %q, %v", got, err)
	}
	// Every candidate was offered, one per line.
	offered, _ := os.ReadFile(stdinFile)
	if string(offered) != "web1\ndb1\n" {
		t.Errorf("fzf was given %q", offered)
	}

	path, _ = fakeFzf(t, "", 130)
	if _, err := pickWithFzf(path, []string{"web1"}, "vsh> ", "header"); !errors.Is(err, errPickCancelled) {
		t.Errorf("Esc in fzf: error = %v, want cancelled", err)
	}
}

func TestPickOneFallsBackWithoutFzf(t *testing.T) {
	old := findFzf
	defer func() { findFzf = old }()

	// With fzf present it is used...
	path, _ := fakeFzf(t, "\nweb1\n", 0)
	findFzf = func() string { return path }
	if got, err := pickOne([]string{"web1"}, "> ", "h"); err != nil || got != "web1" {
		t.Fatalf("with fzf: %q, %v", got, err)
	}

	// ...and without it, the numbered prompt reads the answer from stdin.
	findFzf = func() string { return "" }
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	fmt.Fprintln(w, "2")
	w.Close()
	if got, err := pickOne([]string{"web1", "db1"}, "> ", "h"); err != nil || got != "db1" {
		t.Fatalf("without fzf: %q, %v", got, err)
	}
}

func TestPickNumbered(t *testing.T) {
	items := []string{"web1", "db1", "cache1"}
	cases := []struct {
		name, input, want string
		wantErr           bool
	}{
		{"enter takes the first", "\n", "web1", false},
		{"a number", "3\n", "cache1", false},
		{"free text is a new entry", "root@newhost -p 2222\n", "root@newhost -p 2222", false},
		{"out of range", "9\n", "", true},
		{"zero", "0\n", "", true},
		{"end of input", "", "", true},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		got, err := pickNumbered(items, "host> ", strings.NewReader(tc.input), &out)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%s: = %q, %v; want %q (error: %v)", tc.name, got, err, tc.want, tc.wantErr)
		}
		if !strings.Contains(out.String(), "1) web1") || !strings.Contains(out.String(), "3) cache1") {
			t.Errorf("%s: the list was not shown: %q", tc.name, out.String())
		}
	}

	// A long list is truncated, and says so.
	var many []string
	for i := 0; i < maxNumbered+5; i++ {
		many = append(many, fmt.Sprintf("host%d", i))
	}
	var out bytes.Buffer
	if _, err := pickNumbered(many, "> ", strings.NewReader("\n"), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), fmt.Sprintf("host%d", maxNumbered)) || !strings.Contains(out.String(), "5 more") {
		t.Errorf("long list output: %q", out.String())
	}
	// A hidden entry cannot be chosen by number.
	if _, err := pickNumbered(many, "> ", strings.NewReader(fmt.Sprint(maxNumbered+1)+"\n"), &out); err == nil {
		t.Error("an entry that was not shown was selectable by number")
	}

	// With nothing to list, the prompt simply asks.
	out.Reset()
	if got, err := pickNumbered(nil, "host> ", strings.NewReader("web9\n"), &out); err != nil || got != "web9" {
		t.Errorf("empty list: %q, %v", got, err)
	}
	if _, err := pickNumbered(nil, "host> ", strings.NewReader("\n"), &out); !errors.Is(err, errPickCancelled) {
		t.Errorf("empty list, empty answer: %v, want cancelled", err)
	}
}

// ---------------------------------------------------------------------------
// Logging in when the certificate has run out
// ---------------------------------------------------------------------------

// installCert writes a certificate where `vsh ssh` looks for the global one.
func installCert(t *testing.T, home, keyID string, validity time.Duration) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(testCertB64(t, keyID, []string{"root"}, validity))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519-cert.pub"), data, 0644); err != nil {
		t.Fatal(err)
	}
}

// captureLogin records whether ensureSession decided to log in, and how.
func captureLogin(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	old := runLogin
	runLogin = func(args []string) { calls = append(calls, append([]string{}, args...)) }
	t.Cleanup(func() { runLogin = old })
	return &calls
}

func TestEnsureSession(t *testing.T) {
	t.Run("valid certificate: no login", func(t *testing.T) {
		home := useTempHome(t)
		calls := captureLogin(t)
		installCert(t, home, "alice@example.com@deploy", time.Hour)
		ensureSession()
		if len(*calls) != 0 {
			t.Errorf("logged in with a valid certificate: %v", *calls)
		}
	})

	t.Run("no certificate: login", func(t *testing.T) {
		useTempHome(t)
		calls := captureLogin(t)
		ensureSession()
		if len(*calls) != 1 || len((*calls)[0]) != 0 {
			t.Errorf("login calls = %v, want one with default arguments", *calls)
		}
	})

	// The renewed certificate is for the role the expired one had.
	t.Run("expired certificate: login with the same role", func(t *testing.T) {
		home := useTempHome(t)
		calls := captureLogin(t)
		installCert(t, home, "alice@example.com@deploy", -time.Minute)
		ensureSession()
		if want := [][]string{{"--role", "deploy"}}; !reflect.DeepEqual(*calls, want) {
			t.Errorf("login calls = %v, want %v", *calls, want)
		}
	})

	// A certificate with seconds left would expire mid-handshake.
	t.Run("about to expire: login", func(t *testing.T) {
		home := useTempHome(t)
		calls := captureLogin(t)
		installCert(t, home, "alice@example.com@default", 5*time.Second)
		ensureSession()
		if len(*calls) != 1 {
			t.Errorf("login calls = %v, want one", *calls)
		}
	})

	// Over SSH there is no local browser to open.
	t.Run("remote shell: device flow", func(t *testing.T) {
		home := useTempHome(t)
		calls := captureLogin(t)
		t.Setenv("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
		installCert(t, home, "alice@example.com@deploy", -time.Minute)
		ensureSession()
		if want := [][]string{{"--role", "deploy", "--device"}}; !reflect.DeepEqual(*calls, want) {
			t.Errorf("login calls = %v, want %v", *calls, want)
		}
	})

	t.Run("garbage in the certificate file: login", func(t *testing.T) {
		home := useTempHome(t)
		calls := captureLogin(t)
		os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519-cert.pub"), []byte("not a certificate\n"), 0644)
		ensureSession()
		if len(*calls) != 1 {
			t.Errorf("login calls = %v, want one", *calls)
		}
	})

	// A valid shell-local session is used as it is, even with no global one.
	t.Run("valid local session: no login", func(t *testing.T) {
		useTempHome(t)
		calls := captureLogin(t)
		raw, err := base64.RawURLEncoding.DecodeString(testCertB64(t, "alice@example.com@default", []string{"root"}, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("VSH_LOCAL_CERT", base64.StdEncoding.EncodeToString(raw))
		status := currentCertificate()
		if !status.local || status.needsLogin(time.Now()) {
			t.Fatalf("local certificate status = %+v", status)
		}
		ensureSession()
		if len(*calls) != 0 {
			t.Errorf("logged in over a valid local session: %v", *calls)
		}
	})
}

// Logging out forgets the credential, not which server you use.
func TestLogoutKeepsSavedServer(t *testing.T) {
	home := useTempHome(t)
	if err := saveDefaultServer("https://ca.example.com"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vshDir, "current_server"), []byte("https://ca.example.com"), 0600)
	installCert(t, home, "alice@example.com@default", time.Hour)

	oldArgs := os.Args
	os.Args = []string{"vsh", "logout"}
	defer func() { os.Args = oldArgs }()
	cmdLogout()

	if _, err := os.Stat(filepath.Join(home, ".ssh", "id_ed25519-cert.pub")); !os.IsNotExist(err) {
		t.Error("logout left the certificate in place")
	}
	if got := loadDefaultServer(); got != "https://ca.example.com" {
		t.Errorf("saved server after logout = %q, want it kept", got)
	}
	failIfAsked(t)
	if got, err := resolveServer("", true); err != nil || got != "https://ca.example.com" {
		t.Errorf("login after logout would use %q, %v", got, err)
	}
}
