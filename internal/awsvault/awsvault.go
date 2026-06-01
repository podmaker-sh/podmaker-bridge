// Package awsvault wraps the locally installed `aws-vault` CLI so the
// bridge can list configured profiles and exchange a profile name
// for a short-lived STS credential. We deliberately do not link
// against the aws-vault Go module — the user already trusts the CLI
// on their PATH and we want a minimal binary.
package awsvault

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Credentials is the same shape AWS expects from a `credential_process`
// hook: short-lived STS creds plus the expiration timestamp.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token,omitempty"`
	Region          string    `json:"region,omitempty"`
	Expiration      time.Time `json:"expiration,omitempty"`
}

// Available reports whether `aws-vault` is on the PATH.
func Available() bool {
	_, err := exec.LookPath("aws-vault")
	return err == nil
}

// ListProfiles parses ~/.aws/config for `[profile X]` headers and
// returns them sorted. ~/.aws/credentials is also scanned for the
// `[default]` profile when present. The CLI's own `aws-vault list`
// output is hard to parse reliably across versions, so we read the
// config files directly.
func ListProfiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	scan := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			switch {
			case strings.HasPrefix(name, "profile "):
				out[strings.TrimSpace(strings.TrimPrefix(name, "profile "))] = struct{}{}
			case name == "default":
				out["default"] = struct{}{}
			}
		}
	}
	scan(filepath.Join(home, ".aws", "config"))
	scan(filepath.Join(home, ".aws", "credentials"))
	profiles := make([]string, 0, len(out))
	for p := range out {
		profiles = append(profiles, p)
	}
	// Stable order — sort lexically.
	for i := 1; i < len(profiles); i++ {
		for j := i; j > 0 && profiles[j-1] > profiles[j]; j-- {
			profiles[j], profiles[j-1] = profiles[j-1], profiles[j]
		}
	}
	return profiles, nil
}

// Exec calls `aws-vault exec <profile> --json --no-session=false` and
// returns the parsed credentials. The user may be prompted for a
// passphrase by aws-vault itself (Keychain on macOS); we surface
// any stderr verbatim so the caller can show it.
func Exec(ctx context.Context, profile string) (Credentials, string, error) {
	if profile == "" {
		return Credentials{}, "", fmt.Errorf("awsvault: profile required")
	}
	if !Available() {
		return Credentials{}, "", fmt.Errorf("awsvault: `aws-vault` not found on PATH — install via brew or visit https://github.com/99designs/aws-vault")
	}
	cmd := exec.CommandContext(ctx, "aws-vault", "exec", profile, "--json")
	// Pipe stderr through to the parent so the user sees the
	// pin/passphrase prompt — bridge runs locally, terminal is the
	// user's own.
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return Credentials{}, string(stdout), fmt.Errorf("awsvault: exec failed: %w", err)
	}
	var raw struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return Credentials{}, string(stdout), fmt.Errorf("awsvault: parse stdout: %w", err)
	}
	creds := Credentials{
		AccessKeyID:     raw.AccessKeyID,
		SecretAccessKey: raw.SecretAccessKey,
		SessionToken:    raw.SessionToken,
		Region:          regionForProfile(profile),
	}
	if raw.Expiration != "" {
		if t, perr := time.Parse(time.RFC3339, raw.Expiration); perr == nil {
			creds.Expiration = t
		}
	}
	return creds, "", nil
}

// regionForProfile is a best-effort lookup of the `region` key inside
// ~/.aws/config for the given profile. AWS-vault itself does NOT
// surface the region in its JSON output, so we re-read the config.
func regionForProfile(profile string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(home, ".aws", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()
	header := "[profile " + profile + "]"
	if profile == "default" {
		header = "[default]"
	}
	s := bufio.NewScanner(f)
	in := false
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") {
			in = line == header
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(line, "region") {
			if i := strings.IndexByte(line, '='); i > 0 {
				return strings.TrimSpace(strings.Trim(line[i+1:], "\"' "))
			}
		}
	}
	return ""
}
