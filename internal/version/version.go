// Package version exposes the build version of the voussh binaries.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is overridden at build time via
//
//	-ldflags "-X github.com/voussh/voussh/internal/version.Version=<v>".
//
// When empty, String falls back to the VCS info embedded by the Go toolchain.
var Version = ""

// String returns a human-readable version string such as
//
//	"0.1.0 (a1b2c3d)" or "dev (a1b2c3d-dirty)".
func String() string {
	v := Version
	commit := ""
	modified := false

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		// Use the module version only when it's a real tagged version (i.e.
		// installed via `go install ...@vX.Y.Z`). Local/checkout builds report
		// "(devel)" or a pseudo-version that just repeats the commit below.
		if v == "" && isReleaseVersion(info.Main.Version) {
			v = info.Main.Version
		}
	}

	if v == "" {
		v = "dev"
	}

	if len(commit) > 7 {
		commit = commit[:7]
	}

	if commit == "" {
		return v
	}
	if modified {
		commit += "-dirty"
	}
	return v + " (" + commit + ")"
}

// isReleaseVersion reports whether v is a clean tagged module version
// (e.g. "v0.1.0") rather than "(devel)" or a "-timestamp-commit" pseudo-version.
func isReleaseVersion(v string) bool {
	if v == "" || v == "(devel)" {
		return false
	}
	// Pseudo-versions embed a timestamp+commit as "-YYYYMMDDHHMMSS-<hash>".
	return !strings.Contains(v, "-0.") && !strings.Contains(v, "-20")
}
