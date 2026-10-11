package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestEmbeddedReleasePin(t *testing.T) {
	amd := strings.Repeat("a", 64)
	arm := strings.Repeat("b", 64)
	cases := []struct {
		name, version, amd64, arm64 string
		want                        releasePin
		noPin                       bool // want errNoReleasePin
		bad                         bool // want some other error
	}{
		{name: "both", version: "1.3.0", amd64: amd, arm64: arm, want: releasePin{Tag: "v1.3.0", SHA256: amd, SHA256ARM64: arm}},
		{name: "leading v", version: "v1.3.0", amd64: amd, arm64: arm, want: releasePin{Tag: "v1.3.0", SHA256: amd, SHA256ARM64: arm}},
		{name: "rc", version: "1.3.0-rc.1", amd64: amd, arm64: arm, want: releasePin{Tag: "v1.3.0-rc.1", SHA256: amd, SHA256ARM64: arm}},
		{name: "beta", version: "0.12.0-beta.6", amd64: amd, want: releasePin{Tag: "v0.12.0-beta.6", SHA256: amd}},
		{name: "amd64 only", version: "1.3.0", amd64: amd, want: releasePin{Tag: "v1.3.0", SHA256: amd}},
		{name: "uppercase digest", version: "1.3.0", amd64: strings.ToUpper(amd), want: releasePin{Tag: "v1.3.0", SHA256: amd}},
		{name: "dev build", version: "0.0.1-dev", noPin: true},
		{name: "no digests", version: "1.3.0", noPin: true},
		{name: "arm64 only", version: "1.3.0", arm64: arm, noPin: true},
		{name: "between tags", version: "1.3.0-2-gfe6f405", amd64: amd, noPin: true},
		{name: "dirty", version: "1.3.0-dirty", amd64: amd, noPin: true},
		{name: "snapshot", version: "1.3.1-next", amd64: amd, noPin: true},
		{name: "bare hash", version: "fe6f405", amd64: amd, noPin: true},
		{name: "short amd64", version: "1.3.0", amd64: "abc", bad: true},
		{name: "non-hex arm64", version: "1.3.0", amd64: amd, arm64: strings.Repeat("z", 64), bad: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := embeddedReleasePin(c.version, c.amd64, c.arm64)
			switch {
			case c.noPin:
				if !errors.Is(err, errNoReleasePin) {
					t.Fatalf("err = %v, want errNoReleasePin", err)
				}
			case c.bad:
				if err == nil {
					t.Fatalf("pin = %+v, want an error", got)
				}
			default:
				if err != nil || got != c.want {
					t.Fatalf("pin = %+v, %v; want %+v", got, err, c.want)
				}
			}
		})
	}
}
