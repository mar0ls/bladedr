// Command bladectl is a small, script-friendly client for the bladedr HTTP API.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type client struct {
	base  string
	token string
	http  *http.Client
}

// version is overridden for release artifacts with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bladectl:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	root := flag.NewFlagSet("bladectl", flag.ContinueOnError)
	root.SetOutput(errOut)
	server := root.String("server", env("BLADEDR_SERVER_URL", "http://localhost:8080"), "control-plane URL")
	token := root.String("token", os.Getenv("BLADEDR_TOKEN"), "API bearer token (or BLADEDR_TOKEN)")
	if err := root.Parse(args); err != nil {
		return err
	}
	args = root.Args()
	if len(args) == 0 {
		usage(errOut)
		return errors.New("command required")
	}
	c := &client{base: strings.TrimRight(*server, "/"), token: *token, http: &http.Client{Timeout: 30 * time.Second}}
	switch args[0] {
	case "version":
		fmt.Fprintln(out, version)
		return nil
	case "login":
		return login(c, args[1:], out, errOut)
	case "hosts":
		return hosts(c, args[1:], out, errOut)
	case "scans":
		return scans(c, args[1:], out, errOut)
	case "findings":
		return findings(c, args[1:], out, errOut)
	case "responses":
		return responses(c, args[1:], out, errOut)
	default:
		usage(errOut)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type stringMapFlag map[string]string

func (values stringMapFlag) String() string {
	parts := make([]string, 0, len(values))
	for key, value := range values {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ",")
}

func (values stringMapFlag) Set(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || strings.TrimSpace(key) == "" || value == "" {
		return errors.New("parameter must use non-empty key=value")
	}
	values[key] = value
	return nil
}

func login(c *client, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(errOut)
	username := fs.String("username", "admin", "username")
	password := fs.String("password", "", "password (or BLADEDR_PASSWORD)")
	otp := fs.String("otp", "", "six-digit authenticator code")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *password == "" {
		*password = os.Getenv("BLADEDR_PASSWORD")
	}
	if *password == "" {
		return errors.New("password required; use --password or BLADEDR_PASSWORD")
	}
	return c.request(http.MethodPost, "/api/v1/login", map[string]string{
		"username": *username, "password": *password, "otp": *otp,
	}, out)
}

func hosts(c *client, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("hosts subcommand required: list or add")
	}
	switch args[0] {
	case "list":
		return c.request(http.MethodGet, "/api/v1/hosts", nil, out)
	case "add":
		fs := flag.NewFlagSet("hosts add", flag.ContinueOnError)
		fs.SetOutput(errOut)
		hostname := fs.String("hostname", "", "inventory hostname")
		ip := fs.String("ip", "", "primary IP or DNS name")
		port := fs.Int("ssh-port", 22, "SSH port")
		arch := fs.String("arch", "amd64", "target architecture")
		credential := fs.String("credential", "", "credential id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *hostname == "" && *ip == "" {
			return errors.New("--hostname or --ip is required")
		}
		return c.request(http.MethodPost, "/api/v1/hosts", map[string]any{
			"hostname": *hostname, "primary_ip": *ip, "ssh_port": *port, "arch": *arch, "credential_id": *credential,
		}, out)
	default:
		return fmt.Errorf("unknown hosts subcommand %q", args[0])
	}
}

func scans(c *client, args []string, out, _ io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: bladectl scans start HOST_ID | scans status JOB_ID")
	}
	switch args[0] {
	case "start":
		return c.request(http.MethodPost, "/api/v1/hosts/"+url.PathEscape(args[1])+"/scans", nil, out)
	case "status":
		return c.request(http.MethodGet, "/api/v1/scan-jobs/"+url.PathEscape(args[1]), nil, out)
	default:
		return fmt.Errorf("unknown scans subcommand %q", args[0])
	}
}

func findings(c *client, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("findings subcommand required: list or triage")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("findings list", flag.ContinueOnError)
		fs.SetOutput(errOut)
		host := fs.String("host", "", "host id")
		severity := fs.String("severity", "", "severity")
		status := fs.String("status", "", "triage status")
		query := fs.String("query", "", "full-text query")
		limit := fs.Int("limit", 100, "page size")
		cursor := fs.String("cursor", "", "cursor from X-Next-Cursor")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprint(*limit))
		for key, value := range map[string]string{"host": *host, "severity": *severity, "status": *status, "q": *query, "cursor": *cursor} {
			if value != "" {
				q.Set(key, value)
			}
		}
		return c.request(http.MethodGet, "/api/v1/observations?"+q.Encode(), nil, out)
	case "triage":
		if len(args) != 3 {
			return errors.New("usage: bladectl findings triage OBSERVATION_ID open|acknowledged|resolved|false_positive")
		}
		return c.request(http.MethodPatch, "/api/v1/observations/"+url.PathEscape(args[1]), map[string]string{"status": args[2]}, out)
	default:
		return fmt.Errorf("unknown findings subcommand %q", args[0])
	}
}

func responses(c *client, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("responses subcommand required: list, request, status, or approve")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("responses list", flag.ContinueOnError)
		fs.SetOutput(errOut)
		host := fs.String("host", "", "host id")
		limit := fs.Int("limit", 100, "result limit")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		query := url.Values{"limit": {fmt.Sprint(*limit)}}
		if *host != "" {
			query.Set("host", *host)
		}
		return c.request(http.MethodGet, "/api/v1/responses?"+query.Encode(), nil, out)
	case "request":
		fs := flag.NewFlagSet("responses request", flag.ContinueOnError)
		fs.SetOutput(errOut)
		host := fs.String("host", "", "host id")
		playbook := fs.String("playbook", "", "allowlisted playbook")
		execute := fs.Bool("execute", false, "request execution after separate admin approval; default is dry-run")
		params := stringMapFlag{}
		fs.Var(params, "param", "playbook parameter as key=value (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *host == "" || *playbook == "" {
			return errors.New("--host and --playbook are required")
		}
		return c.request(http.MethodPost, "/api/v1/responses", map[string]any{
			"host_id": *host, "playbook": *playbook, "params": params, "dry_run": !*execute,
		}, out)
	case "status":
		if len(args) != 2 {
			return errors.New("usage: bladectl responses status ACTION_ID")
		}
		return c.request(http.MethodGet, "/api/v1/responses/"+url.PathEscape(args[1]), nil, out)
	case "approve":
		// Two-person control is enforced server-side: approving an action you
		// requested yourself returns 409 unless the deployment opted out.
		if len(args) != 2 {
			return errors.New("usage: bladectl responses approve ACTION_ID")
		}
		return c.request(http.MethodPost, "/api/v1/responses/"+url.PathEscape(args[1])+"/approve", nil, out)
	case "reject":
		fs := flag.NewFlagSet("responses reject", flag.ContinueOnError)
		fs.SetOutput(errOut)
		reason := fs.String("reason", "", "why the action was rejected (recorded on the action and in the audit log)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: bladectl responses reject [--reason TEXT] ACTION_ID")
		}
		return c.request(http.MethodPost, "/api/v1/responses/"+url.PathEscape(fs.Arg(0))+"/reject",
			map[string]any{"reason": *reason}, out)
	default:
		return fmt.Errorf("unknown responses subcommand %q", args[0])
	}
}

func (c *client) request(method, path string, body any, out io.Writer) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if len(data) == 0 {
		fmt.Fprintln(out, "ok")
		return nil
	}
	var value any
	if json.Unmarshal(data, &value) == nil {
		pretty, _ := json.MarshalIndent(value, "", "  ")
		_, err = fmt.Fprintln(out, string(pretty))
		return err
	}
	_, err = out.Write(data)
	return err
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: bladectl [--server URL] [--token TOKEN] <version|login|hosts|scans|findings|responses> ...")
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
