package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// The GitHub REST API, read-only. Everything fetched is DATA: JSON documents
// decoded into typed structs, and zip archives read in memory for a fixed
// allowlist of member base names. Nothing downloaded is written to disk,
// executed, or used as a cache.

const (
	maxJSONBytes     int64 = 32 << 20
	maxArtifactBytes int64 = 64 << 20
	maxMemberBytes   int64 = 64 << 20
)

type apiRun struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	Event        string `json:"event"`
	RunAttempt   int    `json:"run_attempt"`
	HeadSHA      string `json:"head_sha"`
	HeadBranch   string `json:"head_branch"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	CreatedAt    string `json:"created_at"`
	RunStartedAt string `json:"run_started_at"`
	UpdatedAt    string `json:"updated_at"`
	DisplayTitle string `json:"display_title"`
	Repository   struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	HeadRepository struct {
		FullName string `json:"full_name"`
	} `json:"head_repository"`
}

type apiStep struct {
	Name        string `json:"name"`
	Conclusion  string `json:"conclusion"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type apiJob struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	CreatedAt   string    `json:"created_at"`
	StartedAt   string    `json:"started_at"`
	CompletedAt string    `json:"completed_at"`
	RunAttempt  int       `json:"run_attempt"`
	Steps       []apiStep `json:"steps"`
}

type apiArtifact struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	SizeInBytes int64  `json:"size_in_bytes"`
	Expired     bool   `json:"expired"`
	CreatedAt   string `json:"created_at"`
	WorkflowRun struct {
		ID      int64  `json:"id"`
		HeadSHA string `json:"head_sha"`
	} `json:"workflow_run"`
}

type ghClient struct {
	base  *url.URL
	token string
	hc    *http.Client
}

// newGHClient accepts an https API base, or plain http only on a loopback
// address (the in-process test server). A token is optional for public data.
func newGHClient(base, token string) (*ghClient, error) {
	u, err := url.Parse(strings.TrimSuffix(base, "/") + "/")
	if err != nil {
		return nil, fmt.Errorf("api base: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("api base %q: plain http is accepted only on loopback", base)
		}
	default:
		return nil, fmt.Errorf("api base %q: unsupported scheme", base)
	}
	return &ghClient{base: u, token: token, hc: &http.Client{Timeout: 60 * time.Second}}, nil
}

func (c *ghClient) get(ctx context.Context, rel string, limit int64) ([]byte, error) {
	ref, err := url.Parse(rel)
	if err != nil {
		return nil, fmt.Errorf("path %q: %w", rel, err)
	}
	u := c.base.ResolveReference(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", rel, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "culvert-cireport")
	if c.token != "" {
		// net/http drops Authorization when a redirect leaves this host, so
		// an artifact's storage redirect never receives the token.
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rel, redactURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: read: %w", rel, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", rel, limit)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rel, resp.StatusCode)
	}
	return body, nil
}

var errNotFound = errors.New("not found")

// redactURLError drops the query from the URL a transport error names. An
// artifact download redirects to presigned storage whose query IS the
// credential; the error text reaches reports and step summaries, which
// outlive that signature and are readable by anyone with repository read.
func redactURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	u, perr := url.Parse(ue.URL)
	if perr != nil {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return &url.Error{Op: ue.Op, URL: u.String(), Err: ue.Err}
}

func (c *ghClient) getJSON(ctx context.Context, rel string, v any) error {
	body, err := c.get(ctx, rel, maxJSONBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode %s: %w", rel, err)
	}
	return nil
}

func (c *ghClient) run(ctx context.Context, repo string, id int64) (apiRun, error) {
	var r apiRun
	err := c.getJSON(ctx, fmt.Sprintf("repos/%s/actions/runs/%d", repo, id), &r)
	return r, err
}

// jobs lists one attempt's jobs, every page.
func (c *ghClient) jobs(ctx context.Context, repo string, id int64, attempt int) ([]apiJob, error) {
	var all []apiJob
	for page := 1; page <= 20; page++ {
		var resp struct {
			Total int      `json:"total_count"`
			Jobs  []apiJob `json:"jobs"`
		}
		rel := fmt.Sprintf("repos/%s/actions/runs/%d/attempts/%d/jobs?per_page=100&page=%d", repo, id, attempt, page)
		if err := c.getJSON(ctx, rel, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Jobs...)
		if len(resp.Jobs) < 100 || len(all) >= resp.Total {
			return all, nil
		}
	}
	return all, nil
}

func (c *ghClient) runArtifacts(ctx context.Context, repo string, id int64) ([]apiArtifact, error) {
	var resp struct {
		Artifacts []apiArtifact `json:"artifacts"`
	}
	err := c.getJSON(ctx, fmt.Sprintf("repos/%s/actions/runs/%d/artifacts?per_page=100", repo, id), &resp)
	return resp.Artifacts, err
}

// artifactsNamed finds artifacts by exact name across the repository.
func (c *ghClient) artifactsNamed(ctx context.Context, repo, name string) ([]apiArtifact, error) {
	var resp struct {
		Artifacts []apiArtifact `json:"artifacts"`
	}
	err := c.getJSON(ctx, fmt.Sprintf("repos/%s/actions/artifacts?per_page=100&name=%s", repo, url.QueryEscape(name)), &resp)
	return resp.Artifacts, err
}

// workflowRuns lists a workflow's most recent runs, newest first.
func (c *ghClient) workflowRuns(ctx context.Context, repo, file, event string, limit int) ([]apiRun, error) {
	var all []apiRun
	for page := 1; len(all) < limit && page <= 10; page++ {
		var resp struct {
			Runs []apiRun `json:"workflow_runs"`
		}
		rel := fmt.Sprintf("repos/%s/actions/workflows/%s/runs?per_page=100&page=%d", repo, url.PathEscape(file), page)
		if event != "" {
			rel += "&event=" + url.QueryEscape(event)
		}
		if err := c.getJSON(ctx, rel, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Runs...)
		if len(resp.Runs) < 100 {
			break
		}
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// fileAt reads one repository file at a ref through the contents API.
func (c *ghClient) fileAt(ctx context.Context, repo, file, ref string) ([]byte, error) {
	var resp struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	rel := fmt.Sprintf("repos/%s/contents/%s?ref=%s", repo, file, url.QueryEscape(ref))
	if err := c.getJSON(ctx, rel, &resp); err != nil {
		return nil, err
	}
	if resp.Encoding != "base64" {
		return nil, fmt.Errorf("contents %s@%s: unexpected encoding %q", file, ref, resp.Encoding)
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
}

// artifactMembers downloads one artifact and returns ONLY the members whose
// base name is in want. Everything else in the archive — the prebuilt test
// binary in particular — is never read, extracted or executed.
func (c *ghClient) artifactMembers(ctx context.Context, repo string, a apiArtifact, want map[string]bool) (map[string][]byte, error) {
	if a.Expired {
		return nil, fmt.Errorf("artifact %s expired", a.Name)
	}
	if a.SizeInBytes > maxArtifactBytes {
		return nil, fmt.Errorf("artifact %s is %d bytes, over the %d-byte read limit", a.Name, a.SizeInBytes, maxArtifactBytes)
	}
	data, err := c.get(ctx, fmt.Sprintf("repos/%s/actions/artifacts/%d/zip", repo, a.ID), maxArtifactBytes)
	if err != nil {
		return nil, err
	}
	return zipMembers(data, want)
}

// zipMembers reads the allowlisted members of an in-memory archive. A name that
// appears twice is ambiguous and refused rather than resolved by order.
func zipMembers(data []byte, want map[string]bool) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		base := path.Base(f.Name)
		if !want[base] || f.FileInfo().IsDir() {
			continue
		}
		if _, dup := out[base]; dup {
			return nil, fmt.Errorf("archive carries %q twice", base)
		}
		if f.UncompressedSize64 > uint64(maxMemberBytes) {
			return nil, fmt.Errorf("member %s declares %d bytes, over the limit", f.Name, f.UncompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", f.Name, err)
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxMemberBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Name, err)
		}
		if int64(len(b)) > maxMemberBytes {
			return nil, fmt.Errorf("member %s exceeds the limit", f.Name)
		}
		out[base] = b
	}
	return out, nil
}
