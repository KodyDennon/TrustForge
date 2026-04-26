// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// UnveilEntry is a path/permission pair to be passed to unveil(2).
//
// Permissions follow the OpenBSD convention:
//   r = read, w = write, x = execute, c = create.
type UnveilEntry struct {
	Path string `yaml:"path"`
	Perm string `yaml:"perm"`
}

// Policy is the structure of pledge-policy.yaml. It is the only thing
// supervisor consumers should depend on; the daemon side of the
// /v1/decide call carries the same fields by name.
type Policy struct {
	Name     string        `yaml:"name"`
	Exec     []string      `yaml:"exec"`
	Promises []string      `yaml:"promises"`
	ExecProm []string      `yaml:"exec_promises"`
	Unveil   []UnveilEntry `yaml:"unveil"`
	Env      []string      `yaml:"env,omitempty"`
	Cwd      string        `yaml:"cwd,omitempty"`
}

// validate returns nil iff the policy is internally consistent enough
// to attempt supervision.
func (p *Policy) validate() error {
	if p.Name == "" {
		return errors.New("policy.name is required")
	}
	if len(p.Exec) == 0 {
		return errors.New("policy.exec is required (at least argv0)")
	}
	if len(p.Promises) == 0 {
		return errors.New("policy.promises is required (use [] to drop all)")
	}
	for i, u := range p.Unveil {
		if u.Path == "" {
			return fmt.Errorf("policy.unveil[%d].path empty", i)
		}
		if !validUnveilPerm(u.Perm) {
			return fmt.Errorf("policy.unveil[%d].perm %q is not a subset of rwxc", i, u.Perm)
		}
	}
	for _, pr := range p.Promises {
		if !validPromise(pr) {
			return fmt.Errorf("policy.promises: %q is not a known pledge(2) promise", pr)
		}
	}
	for _, pr := range p.ExecProm {
		if !validPromise(pr) {
			return fmt.Errorf("policy.exec_promises: %q is not a known pledge(2) promise", pr)
		}
	}
	return nil
}

// loadPolicy reads a YAML policy file (or, if path is empty, builds a
// "deny everything" default policy from cli args).
func loadPolicy(path string, cliArgs []string) (*Policy, error) {
	if path == "" {
		// CLI-only mode: just exec, with the most restrictive default.
		if len(cliArgs) == 0 {
			return nil, errors.New("either --policy or argv must be provided")
		}
		return &Policy{
			Name:     "cli-default",
			Exec:     cliArgs,
			Promises: []string{"stdio"},
		}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := parsePolicyYAML(raw)
	if err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// parsePolicyYAML is a tiny YAML-subset parser that handles the shape
// of pledge-policy.yaml without taking on a heavyweight YAML
// dependency. It supports:
//
//   - top-level scalar fields:   key: value
//   - top-level sequence:        key:
//                                  - value
//   - top-level sequence of
//     mapping (Unveil only):     unveil:
//                                  - path: /etc
//                                    perm: r
//
// This is sufficient for the supervisor; production deployments can
// regenerate equivalent JSON.
func parsePolicyYAML(raw []byte) (*Policy, error) {
	p := &Policy{}
	lines := strings.Split(string(raw), "\n")
	var currentList *[]string
	var inUnveil bool
	var pending UnveilEntry
	flush := func() {
		if pending.Path != "" {
			p.Unveil = append(p.Unveil, pending)
			pending = UnveilEntry{}
		}
	}
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		line := strings.TrimRight(raw, "\r")
		// strip comments (very rough: any '#' not in quotes)
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}

		// Top-level key (no leading whitespace).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			inUnveil = false
			currentList = nil
			key, val, ok := splitKey(trim)
			if !ok {
				return nil, fmt.Errorf("policy line %d: %q not key:value", i+1, trim)
			}
			val = strings.TrimSpace(val)
			switch key {
			case "name":
				p.Name = unquote(val)
			case "cwd":
				p.Cwd = unquote(val)
			case "exec":
				if val != "" {
					p.Exec = parseInlineSeq(val)
				} else {
					currentList = &p.Exec
				}
			case "promises":
				if val != "" {
					p.Promises = parseInlineSeq(val)
				} else {
					currentList = &p.Promises
				}
			case "exec_promises":
				if val != "" {
					p.ExecProm = parseInlineSeq(val)
				} else {
					currentList = &p.ExecProm
				}
			case "env":
				if val != "" {
					p.Env = parseInlineSeq(val)
				} else {
					currentList = &p.Env
				}
			case "unveil":
				inUnveil = true
			default:
				// ignore unknown top-level keys for forward compat
			}
			continue
		}

		// Indented line.
		if inUnveil {
			if strings.HasPrefix(trim, "- ") {
				flush()
				rest := strings.TrimSpace(strings.TrimPrefix(trim, "- "))
				k, v, ok := splitKey(rest)
				if ok {
					switch k {
					case "path":
						pending.Path = unquote(strings.TrimSpace(v))
					case "perm":
						pending.Perm = unquote(strings.TrimSpace(v))
					}
				}
			} else {
				k, v, ok := splitKey(trim)
				if ok {
					switch k {
					case "path":
						pending.Path = unquote(strings.TrimSpace(v))
					case "perm":
						pending.Perm = unquote(strings.TrimSpace(v))
					}
				}
			}
			continue
		}

		if currentList != nil {
			if strings.HasPrefix(trim, "- ") {
				val := strings.TrimSpace(strings.TrimPrefix(trim, "- "))
				*currentList = append(*currentList, unquote(val))
			}
		}
	}
	flush()
	return p, nil
}

func splitKey(s string) (string, string, bool) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), s[idx+1:], true
}

func parseInlineSeq(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		// treat as bare scalar
		return []string{unquote(s)}
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, unquote(p))
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' ||
		s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func validUnveilPerm(p string) bool {
	if p == "" {
		return true // empty means "no access"
	}
	for _, c := range p {
		switch c {
		case 'r', 'w', 'x', 'c':
		default:
			return false
		}
	}
	return true
}

// knownPromises is the set of pledge(2) promises understood as of
// OpenBSD 7.4. New releases extend this; unknown promises are
// rejected at load to surface typos early.
var knownPromises = map[string]struct{}{
	"audio": {}, "bpf": {}, "chown": {}, "cpath": {}, "disklabel": {},
	"dns": {}, "drm": {}, "error": {}, "exec": {}, "fattr": {},
	"flock": {}, "getpw": {}, "id": {}, "inet": {}, "ioctl": {},
	"mcast": {}, "pf": {}, "pipe": {}, "proc": {}, "prot_exec": {},
	"ps": {}, "recvfd": {}, "route": {}, "rpath": {}, "sendfd": {},
	"settime": {}, "stdio": {}, "tape": {}, "tmppath": {}, "tty": {},
	"unix": {}, "unveil": {}, "vminfo": {}, "vmm": {}, "wpath": {},
	"wroute": {},
}

func validPromise(p string) bool {
	_, ok := knownPromises[p]
	return ok
}
