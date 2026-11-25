package reqlog

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScrubCredentialsRedactsSecrets(t *testing.T) {
	proxyErr := &url.Error{
		Op:  "Post",
		URL: "https://quick.example.amazonaws.com/v1/chat",
		Err: errors.New("proxyconnect tcp: dial http://alice:s3cretPass@proxy.local:8080: connection refused"),
	}
	cases := []struct {
		name   string
		in     string
		secret []string
	}{
		{"url.Error proxy userinfo", proxyErr.Error(), []string{"alice", "s3cretPass"}},
		{"socks5 proxy", "using proxy socks5h://bob:hunter22@10.0.0.1:1080", []string{"bob", "hunter22"}},
		{"bearer header", "Authorization: Bearer abcdefghijklmnop.qrstuv", []string{"abcdefghijklmnop"}},
		{"basic header", `header authorization: Basic dXNlcjpwYXNzd29yZA==`, []string{"dXNlcjpwYXNzd29yZA"}},
		{"bearer url encoded", "auth=Bearer%20abcdefghijklmnop", []string{"abcdefghijklmnop"}},
		{"api key", "client used qk_0123456789abcdef0123456789abcdef01234567", []string{"0123456789abcdef0123"}},
		{"admin key", "panel key qka_0123456789abcdef0123456789abcdef01234567 rejected", []string{"0123456789abcdef0123"}},
		{"jwt", "id eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P", []string{"SflKxwRJSMeKKF2QT4fwpMeJf36P"}},
		{"json refresh token", `{"refresh_token":"rt-AbCdEf123456","expires_in":3600}`, []string{"rt-AbCdEf123456"}},
		{"json access token", `{"accessToken": "at.XYZ987654321"}`, []string{"at.XYZ987654321"}},
		{"query access token", "GET /cb?access_token=tok12345678&state=x", []string{"tok12345678"}},
		{"client secret form", "client_secret=cs_live_9876543210&grant_type=refresh_token", []string{"cs_live_9876543210"}},
		{"password field", "password: hunter2hunter2", []string{"hunter2hunter2"}},
		{"x-api-key header", "X-Api-Key: sk-abcdef0123456789", []string{"sk-abcdef0123456789"}},
		{"hyphenated api key", "failed key qk_my-custom-prod-key-1234 rejected", []string{"my-custom-prod-key-1234"}},
		{"hyphenated admin key", "panel qka_team-admin-key_9876 denied", []string{"team-admin-key_9876"}},
		{"query ?token=", "wss://cell001.example.aws.dev/streaming?token=opaque_secret_tok_99&foo=bar", []string{"opaque_secret_tok_99"}},
		{"query &token=", "GET /stream?region=us-east-1&token=anotherSecretToken42&x=1", []string{"anotherSecretToken42"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := ScrubCredentials(tc.in)
			for _, s := range tc.secret {
				if strings.Contains(out, s) {
					t.Fatalf("secret %q leaked: %q", s, out)
				}
			}
			if !strings.Contains(out, "REDACTED") && !strings.Contains(out, "***@") {
				t.Fatalf("no redaction marker in %q", out)
			}
			if again := ScrubCredentials(out); again != out {
				t.Fatalf("scrub not idempotent:\n first=%q\nsecond=%q", out, again)
			}
		})
	}
}

func TestScrubCredentialsKeepsBenignText(t *testing.T) {
	benign := []string{
		"[auth] token refreshed successfully for 2 account(s)",
		"Look at req.Header and ctx.Done()",
		"listening on http://127.0.0.1:8045/panel/",
		"basic authentication is not configured",
		"[pool] max_tokens=4096 prompt_tokens=120",
		"api_key or admin_key is empty/default while listening on non-loopback 0.0.0.0:8045",
	}
	for _, in := range benign {
		if out := ScrubCredentials(in); out != in {
			t.Errorf("benign text altered:\n  in=%q\n out=%q", in, out)
		}
	}
	if ScrubCredentials("") != "" {
		t.Fatal("empty string must stay empty")
	}
}

func TestRecorderScrubsLogsAndErrors(t *testing.T) {
	r := New("", false)
	defer r.Close()
	_, _ = r.Write([]byte("dial http://u:pw123456@proxy:3128 failed\n"))
	logs := r.RecentLogs(10)
	if len(logs) != 1 || strings.Contains(logs[0].Text, "pw123456") {
		t.Fatalf("log line not scrubbed: %+v", logs)
	}
	r.Record(Entry{ID: "req_1", Status: 502, ErrorMessage: "upstream said refresh_token=abcdef123456 invalid"})
	got := r.Recent(1)
	if len(got) != 1 || strings.Contains(got[0].ErrorMessage, "abcdef123456") {
		t.Fatalf("entry error not scrubbed: %+v", got)
	}
}

// Clear(true) racing Close must never send on a closed channel (P2-21).
func TestRecorderClearCloseConcurrent(t *testing.T) {
	for iter := 0; iter < 30; iter++ {
		dir := t.TempDir()
		r := New(dir, true)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				for j := 0; j < 20; j++ {
					if i%2 == 0 {
						_ = r.Clear(true)
					} else {
						r.Record(Entry{ID: NewRequestID(), Status: 200})
					}
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(time.Duration(iter%5) * 100 * time.Microsecond)
			r.Close()
		}()
		close(start)

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Clear/Close deadlocked")
		}
		// Calls after Close must stay safe and idempotent.
		if err := r.Clear(true); err != nil {
			t.Fatalf("Clear after Close: %v", err)
		}
		r.Close()
		r.Record(Entry{ID: "after-close", Status: 200})
	}
}

func TestRecorderClearRemovesArchive(t *testing.T) {
	dir := t.TempDir()
	r := New(dir, true)
	r.Record(Entry{ID: "req_a", Timestamp: time.Now().UnixMilli(), Status: 200})
	r.Close()
	matches, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(matches) == 0 {
		t.Fatal("expected an archive file after Close")
	}

	r2 := New(dir, true)
	defer r2.Close()
	if n := r2.LoadFromArchive(); n != 1 {
		t.Fatalf("LoadFromArchive = %d, want 1", n)
	}
	if err := r2.Clear(true); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	matches, _ = filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(matches) != 0 {
		t.Fatalf("archive files remain after Clear(true): %v", matches)
	}
	if len(r2.Recent(10)) != 0 {
		t.Fatal("entries remain after Clear")
	}
}

func TestLogDirsArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	base := t.TempDir()
	archiveDir := filepath.Join(base, "request-logs")
	r := New(archiveDir, true)
	r.Close()
	logDir := filepath.Join(base, "logs")
	w, err := NewRotatingFileWriter(filepath.Join(logDir, "app.log"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	for _, d := range []string{archiveDir, logDir} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s perm = %o, want no group/other access", d, perm)
		}
	}
}

func TestRotatingFileWriterScrubsAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w, err := NewRotatingFileWriter(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("proxy http://user:topsecret99@p:1 down\n"))
	_, _ = w.Write([]byte(strings.Repeat("x", 80) + "\n"))
	_ = w.Close()
	var all string
	for _, p := range []string{path, path + ".1"} {
		b, _ := os.ReadFile(p)
		all += string(b)
	}
	if strings.Contains(all, "topsecret99") {
		t.Fatalf("file log leaked credential: %q", all)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotation backup: %v", err)
	}
}

func TestRecentAndRecentLogsClampLimitToMax(t *testing.T) {
	r := New("", false)
	defer r.Close()
	for i := 0; i < defaultMaxEntries; i++ {
		r.Record(Entry{ID: NewRequestID(), Status: 200})
	}
	if got := len(r.Recent(defaultMaxEntries + 500)); got != defaultMaxEntries {
		t.Fatalf("Recent(limit > max) returned %d entries, want %d", got, defaultMaxEntries)
	}
	if got := len(r.Recent(0)); got != 100 {
		t.Fatalf("Recent(0) returned %d entries, want default 100", got)
	}

	for i := 0; i < defaultMaxLogs; i++ {
		_, _ = r.Write([]byte("line\n"))
	}
	if got := len(r.RecentLogs(defaultMaxLogs + 500)); got != defaultMaxLogs {
		t.Fatalf("RecentLogs(limit > max) returned %d lines, want %d", got, defaultMaxLogs)
	}
	if got := len(r.RecentLogs(-5)); got != 200 {
		t.Fatalf("RecentLogs(-5) returned %d lines, want default 200", got)
	}
}
