package panel

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"awsquick2api/internal/reqlog"
)

const maxExportLogFileBytes = 10 << 20 // 10 MiB per log file safety cap

// handleLogsExport packages scrubbed runtime logs into a temporary ZIP archive
// and serves it cleanly with http.ServeContent so partial write failures never
// emit a truncated archive to the browser.
func (p *Panel) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	tmp, err := os.CreateTemp("", "awsquick2api-logs-*.zip")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create export archive: " + err.Error()})
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	zw := zip.NewWriter(tmp)
	added := 0

	// 1. Export on-disk rotating log file(s), scrubbing every line defensively.
	if p.cfg.LogFilePath != "" {
		for _, candidate := range []string{p.cfg.LogFilePath, p.cfg.LogFilePath + ".1"} {
			if ok, werr := addScrubbedFileToZip(zw, filepath.Base(candidate), candidate); werr != nil {
				_ = zw.Close()
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "pack log file: " + werr.Error()})
				return
			} else if ok {
				added++
			}
		}
	}

	// 2. Include the in-memory scrubbed log ring buffer so headless/ephemeral runs still export logs.
	if p.cfg.ReqLog != nil {
		if lines := p.cfg.ReqLog.RecentLogs(1000); len(lines) > 0 {
			fw, err := zw.Create("recent-runtime.log")
			if err != nil {
				_ = zw.Close()
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "pack memory logs: " + err.Error()})
				return
			}
			for _, ln := range lines {
				ts := time.UnixMilli(ln.Timestamp).UTC().Format(time.RFC3339)
				_, _ = fmt.Fprintf(fw, "[%s] %s\n", ts, reqlog.ScrubCredentials(ln.Text))
			}
			added++
		}
	}

	if err := zw.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "finalize zip: " + err.Error()})
		return
	}
	if added == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "暂无可导出的运行日志"})
		return
	}
	info, err := tmp.Stat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "stat export archive: " + err.Error()})
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "seek export archive: " + err.Error()})
		return
	}
	filename := fmt.Sprintf("awsquick2api-logs-%s.zip", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeContent(w, r, filename, info.ModTime(), tmp)
}

func addScrubbedFileToZip(zw *zip.Writer, entryName, path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	fw, err := zw.Create(entryName)
	if err != nil {
		return false, err
	}
	rd := bufio.NewReaderSize(io.LimitReader(f, maxExportLogFileBytes), 32*1024)
	for {
		line, rerr := rd.ReadString('\n')
		if len(line) > 0 {
			scrubbed := reqlog.ScrubCredentials(strings.TrimRight(line, "\r\n"))
			if _, werr := io.WriteString(fw, scrubbed+"\n"); werr != nil {
				return false, werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return false, rerr
		}
	}
	return true, nil
}
