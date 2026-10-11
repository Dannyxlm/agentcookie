// Package tincantest provides a fake `tincan` executable for tests. It is
// a /bin/sh script written into a temp dir, so it runs on Linux and macOS
// CI alike, and it never contacts a relay.
package tincantest

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// script answers each subcommand ($1) from files in its directory:
// <cmd>.out (stdout), <cmd>.err (stderr) and <cmd>.exit (exit code). Every
// call is written to its own file, call.<n>: TINCAN_CONFIG on the first
// line, then the args joined by \x1f (args may hold newlines).
const script = `#!/bin/sh
dir="$(dirname "$0")"
args=""
for a in "$@"; do
  if [ -z "$args" ]; then args="$a"; else args="$args$(printf '\037')$a"; fi
done
n=$(ls "$dir" | grep -c '^call\.')
printf '%s\n%s' "$TINCAN_CONFIG" "$args" > "$dir/call.$((n + 1))"
cmd="$1"
[ -f "$dir/$cmd.err" ] && cat "$dir/$cmd.err" >&2
[ -f "$dir/$cmd.out" ] && cat "$dir/$cmd.out"
code=0
[ -f "$dir/$cmd.exit" ] && code="$(cat "$dir/$cmd.exit")"
exit "$code"
`

// Fake is one fake tincan binary.
type Fake struct {
	t    testing.TB
	Dir  string
	Path string
}

// Call is one recorded invocation.
type Call struct {
	Config string
	Args   []string
}

// New writes a fake tincan into a fresh temp dir.
func New(t testing.TB) *Fake {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tincan")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Fake{t: t, Dir: dir, Path: path}
}

// Set makes subcommand cmd print stdout and stderr and exit with code.
func (f *Fake) Set(cmd, stdout, stderr string, code int) {
	f.t.Helper()
	f.write(cmd+".out", stdout)
	f.write(cmd+".err", stderr)
	f.write(cmd+".exit", strconv.Itoa(code))
}

func (f *Fake) write(name, body string) {
	f.t.Helper()
	p := filepath.Join(f.Dir, name)
	if body == "" && !strings.HasSuffix(name, ".exit") {
		_ = os.Remove(p)
		return
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// Calls returns every recorded invocation in order.
func (f *Fake) Calls() []Call {
	f.t.Helper()
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		f.t.Fatal(err)
	}
	var nums []int
	for _, e := range entries {
		if n, ok := strings.CutPrefix(e.Name(), "call."); ok {
			if i, err := strconv.Atoi(n); err == nil {
				nums = append(nums, i)
			}
		}
	}
	sort.Ints(nums)
	out := make([]Call, 0, len(nums))
	for _, i := range nums {
		data, err := os.ReadFile(filepath.Join(f.Dir, "call."+strconv.Itoa(i)))
		if err != nil {
			f.t.Fatal(err)
		}
		cfg, args, _ := strings.Cut(string(data), "\n")
		out = append(out, Call{Config: cfg, Args: strings.Split(args, "\x1f")})
	}
	return out
}

// CallsTo returns the recorded invocations of subcommand cmd.
func (f *Fake) CallsTo(cmd string) []Call {
	var out []Call
	for _, c := range f.Calls() {
		if len(c.Args) > 0 && c.Args[0] == cmd {
			out = append(out, c)
		}
	}
	return out
}

// Reset forgets recorded calls.
func (f *Fake) Reset() {
	entries, _ := os.ReadDir(f.Dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "call.") {
			_ = os.Remove(filepath.Join(f.Dir, e.Name()))
		}
	}
}
