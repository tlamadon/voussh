package main

// Which voussh server a command talks to. The choice is made once and kept:
//
//	--server flag  >  $VSH_SERVER  >  the saved default  >  ask (once) and save
//
// The saved default lives in its own file, default_server. It is distinct
// from current_server, which records where the current global certificate
// came from and is cleared on logout; logging out forgets the credential, not
// which server you use.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func defaultServerPath() string { return filepath.Join(vshDir, "default_server") }

func normalizeServerURL(url string) string {
	return strings.TrimRight(strings.TrimSpace(url), "/")
}

// loadDefaultServer returns the saved default, or "" if none has been chosen.
func loadDefaultServer() string {
	data, err := os.ReadFile(defaultServerPath())
	if err != nil {
		return ""
	}
	return normalizeServerURL(string(data))
}

func saveDefaultServer(url string) error {
	url = normalizeServerURL(url)
	if url == "" {
		return errors.New("server URL must not be empty")
	}
	if err := os.MkdirAll(vshDir, 0700); err != nil {
		return err
	}
	if err := writeFileAtomic(defaultServerPath(), []byte(url+"\n"), 0600); err != nil {
		return err
	}
	addServerToHistory(url)
	return nil
}

// chooseServer asks the user which server to use. It is a variable so tests
// can answer for the user.
var chooseServer = pickServer

// notef prints a notice for the user. Eval mode captures everything vsh
// prints and feeds it to the shell, so notices are withheld there.
func notef(format string, args ...any) {
	if os.Getenv("VSH_EVAL_MODE") != "1" {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

// resolveServer returns the server a command should use. explicit is the
// value of its --server flag. When nothing is configured and interactive is
// true, the user is asked once and the answer becomes the default; a
// non-interactive command fails instead of prompting.
func resolveServer(explicit string, interactive bool) (string, error) {
	if explicit = normalizeServerURL(explicit); explicit != "" {
		// An explicit server is for this invocation only — unless there is no
		// default yet, in which case the first server you name is clearly the
		// one you use.
		if loadDefaultServer() == "" && os.Getenv("VSH_SERVER") == "" {
			if err := saveDefaultServer(explicit); err == nil {
				notef("Saved %s as your server. Change it with: vsh server", explicit)
			}
		}
		return explicit, nil
	}
	if env := normalizeServerURL(os.Getenv("VSH_SERVER")); env != "" {
		return env, nil
	}
	if saved := loadDefaultServer(); saved != "" {
		return saved, nil
	}

	// Nothing chosen yet. Someone upgrading from a version without a saved
	// default has a history instead: a single entry is unambiguous and is
	// adopted without a question.
	chosen := ""
	if history := getServerHistory(); len(history) == 1 {
		chosen = history[0]
	} else if !interactive {
		return "", errors.New("no server configured. Use --server, set VSH_SERVER, or run: vsh server <url>")
	} else {
		picked, err := chooseServer()
		if err != nil {
			return "", err
		}
		chosen = picked
	}
	if chosen = normalizeServerURL(chosen); chosen == "" {
		return "", errors.New("no server given")
	}
	if err := saveDefaultServer(chosen); err != nil {
		return "", fmt.Errorf("failed to save server: %w", err)
	}
	notef("Using %s from now on. Change it with: vsh server", chosen)
	return chosen, nil
}

// cmdServer shows or changes the saved default server.
func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	pick := fs.Bool("pick", false, "Choose from previously used servers")
	clear := fs.Bool("clear", false, "Forget the saved server")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: vsh server            Show the server vsh uses")
		fmt.Fprintln(os.Stderr, "       vsh server <url>      Use this server from now on")
		fmt.Fprintln(os.Stderr, "       vsh server --pick     Choose from previously used servers")
		fmt.Fprintln(os.Stderr, "       vsh server --clear    Forget the saved server")
	}
	fs.Parse(args)

	switch {
	case *clear:
		if err := os.Remove(defaultServerPath()); err != nil && !os.IsNotExist(err) {
			fatalf("failed to forget server: %v", err)
		}
		fmt.Println("Saved server cleared")

	case *pick:
		picked, err := pickServer()
		if err != nil {
			fatalf("%v", err)
		}
		setDefaultServer(picked)

	case fs.NArg() == 1:
		setDefaultServer(fs.Arg(0))

	case fs.NArg() == 0:
		saved := loadDefaultServer()
		if env := normalizeServerURL(os.Getenv("VSH_SERVER")); env != "" {
			fmt.Printf("%s (from $VSH_SERVER)\n", env)
			if saved != "" && saved != env {
				fmt.Printf("Saved server, currently overridden: %s\n", saved)
			}
			return
		}
		if saved == "" {
			fmt.Println("No server saved. Set one with: vsh server <url>")
			return
		}
		fmt.Println(saved)

	default:
		fs.Usage()
		os.Exit(1)
	}
}

func setDefaultServer(url string) {
	url = normalizeServerURL(url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fatalf("server must be an http:// or https:// URL, got %q", url)
	}
	if err := saveDefaultServer(url); err != nil {
		fatalf("failed to save server: %v", err)
	}
	fmt.Printf("Using %s from now on\n", url)
	if env := normalizeServerURL(os.Getenv("VSH_SERVER")); env != "" && env != url {
		fmt.Printf("Note: $VSH_SERVER is set to %s and takes precedence while it is.\n", env)
	}
}

// pickServer lets the user choose among previously used servers, or type a
// new one, through the same finder as the host picker.
func pickServer() (string, error) {
	history := getServerHistory()
	if len(history) == 0 {
		fmt.Fprint(os.Stderr, "Enter server URL: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	choice, err := pickOne(history, "server> ", "Enter: use this server · or type a new URL")
	if err != nil {
		return "", err
	}
	return choice, nil
}
