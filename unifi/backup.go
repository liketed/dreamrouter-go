package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Backup is one of the router's automatic backups of the Network
// application's settings (Settings → System → Backups).
type Backup struct {
	Filename    string // e.g. "autobackup_10.6.106_20260930_2330_1790811000005.unf"
	Version     string // Network application version that made it
	Time        time.Time
	Size        int64 // bytes
	KeepForever bool
}

// ListBackups returns the router's automatic backups, oldest first.
func (c *Client) ListBackups(ctx context.Context) ([]Backup, error) {
	var env classicEnvelope
	if err := c.do(ctx, http.MethodPost, c.classic("/cmd/backup"), map[string]any{"cmd": "list-backups"}, &env); err != nil {
		return nil, err
	}
	var raw []struct {
		Filename    string `json:"filename"`
		Version     string `json:"version"`
		Time        int64  `json:"time"` // milliseconds
		Size        int64  `json:"size"`
		KeepForever bool   `json:"keep_forever"`
	}
	if err := decodeClassic(http.MethodPost, "/cmd/backup", env, &raw); err != nil {
		return nil, err
	}
	out := make([]Backup, 0, len(raw))
	for _, b := range raw {
		out = append(out, Backup{Filename: b.Filename, Version: b.Version, Time: time.UnixMilli(b.Time), Size: b.Size, KeepForever: b.KeepForever})
	}
	// Oldest first.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Time.Before(out[j-1].Time); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// DownloadBackup makes a fresh backup and returns it (an encrypted .unf
// file). historyDays is how many days of statistics to include; 0 means
// settings only. The router doesn't add it to the automatic backups.
func (c *Client) DownloadBackup(ctx context.Context, historyDays int) ([]byte, error) {
	var env classicEnvelope
	if err := c.do(ctx, http.MethodPost, c.classic("/cmd/backup"), map[string]any{"cmd": "backup", "days": historyDays}, &env); err != nil {
		return nil, err
	}
	var made []struct {
		URL string `json:"url"`
	}
	if err := decodeClassic(http.MethodPost, "/cmd/backup", env, &made); err != nil {
		return nil, err
	}
	if len(made) == 0 || !strings.HasPrefix(made[0].URL, "/dl/") {
		return nil, fmt.Errorf("POST /cmd/backup: the router didn't say where the backup is")
	}
	return c.download(ctx, made[0].URL)
}

// DownloadAutoBackup returns one of the automatic backups, by file name.
func (c *Client) DownloadAutoBackup(ctx context.Context, filename string) ([]byte, error) {
	if err := checkBackupName(filename); err != nil {
		return nil, err
	}
	return c.download(ctx, "/dl/autobackup/"+filename)
}

// DeleteAutoBackup deletes one of the automatic backups, by file name.
func (c *Client) DeleteAutoBackup(ctx context.Context, filename string) error {
	if err := checkBackupName(filename); err != nil {
		return err
	}
	var env classicEnvelope
	return c.write(ctx, http.MethodPost, c.classic("/cmd/backup"), map[string]any{"cmd": "delete-backup", "filename": filename}, &env)
}

func checkBackupName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || !strings.HasSuffix(name, ".unf") {
		return fmt.Errorf("%q is not a backup file name (e.g. autobackup_10.6.106_20260930_2330_1790811000005.unf)", name)
	}
	return nil
}

func (c *Client) download(ctx context.Context, path string) ([]byte, error) {
	var data []byte
	if err := c.do(ctx, http.MethodGet, c.network+path, nil, &data); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("GET %s: empty backup", path)
	}
	return data, nil
}

// BackupSchedule is when the router makes automatic backups.
type BackupSchedule struct {
	Enabled     bool
	Cron        string // 5-field cron expression, e.g. "30 0 1 * *" (00:30 on the 1st of each month)
	Timezone    string
	HistoryDays int // days of statistics included; 0 means settings only
}

type superMgmt struct {
	ID          string `json:"_id"`
	Enabled     bool   `json:"autobackup_enabled"`
	Cron        string `json:"autobackup_cron_expr"`
	Timezone    string `json:"autobackup_timezone"`
	HistoryDays int    `json:"autobackup_days"`
}

func (c *Client) superMgmt(ctx context.Context) (superMgmt, error) {
	var settings []struct {
		Key string `json:"key"`
		superMgmt
	}
	if err := c.classicGet(ctx, "/rest/setting", &settings); err != nil {
		return superMgmt{}, err
	}
	for _, s := range settings {
		if s.Key == "super_mgmt" {
			return s.superMgmt, nil
		}
	}
	return superMgmt{}, fmt.Errorf("the router has no super_mgmt setting")
}

// GetBackupSchedule returns the automatic backup schedule.
func (c *Client) GetBackupSchedule(ctx context.Context) (BackupSchedule, error) {
	s, err := c.superMgmt(ctx)
	return BackupSchedule{Enabled: s.Enabled, Cron: s.Cron, Timezone: s.Timezone, HistoryDays: s.HistoryDays}, err
}

// SetBackupSchedule changes the automatic backup schedule. An empty
// Timezone keeps the current one.
func (c *Client) SetBackupSchedule(ctx context.Context, b BackupSchedule) (BackupSchedule, error) {
	cur, err := c.superMgmt(ctx)
	if err != nil {
		return BackupSchedule{}, err
	}
	if b.Timezone == "" {
		b.Timezone = cur.Timezone
	}
	fields := map[string]any{"autobackup_enabled": b.Enabled, "autobackup_cron_expr": b.Cron,
		"autobackup_timezone": b.Timezone, "autobackup_days": b.HistoryDays}
	var env classicEnvelope
	if err := c.write(ctx, http.MethodPut, c.classic("/rest/setting/super_mgmt/"+cur.ID), fields, &env); err != nil {
		return BackupSchedule{}, err
	}
	return c.GetBackupSchedule(ctx)
}

// StagedBackup is a backup uploaded to the router and checked by it, ready
// to restore with RestoreBackup.
type StagedBackup struct {
	ID       string    // pass to RestoreBackup
	Version  string    // Network application version that made the backup
	Time     time.Time // when the backup was made
	Filename string
	Size     int64
	Sites    []string // site names in the backup, e.g. ["default"]
}

// UploadBackup sends a backup file (.unf) to the router, which checks it and
// keeps it ready to restore. Nothing changes until RestoreBackup is called.
// A file that isn't a backup gives an error with CodeInvalidBackup.
func (c *Client) UploadBackup(ctx context.Context, data []byte, filename string) (StagedBackup, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		return StagedBackup{}, err
	}
	if _, err := part.Write(data); err != nil {
		return StagedBackup{}, err
	}
	if err := w.Close(); err != nil {
		return StagedBackup{}, err
	}
	var env classicEnvelope
	if err := c.do(ctx, http.MethodPost, c.network+"/upload/backup", rawBody{buf.Bytes(), w.FormDataContentType()}, &env); err != nil {
		return StagedBackup{}, err
	}
	var raw []struct {
		ID        string `json:"backup_id"`
		Version   string `json:"version"`
		Filename  string `json:"filename"`
		Size      int64  `json:"filesize"`
		Timestamp string `json:"timestamp"` // milliseconds, as a string
		Sites     []struct {
			Name string `json:"name"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(env.Data, &raw); err != nil || len(raw) == 0 || raw[0].ID == "" {
		return StagedBackup{}, fmt.Errorf("POST /upload/backup: unexpected response %s", env.Data)
	}
	r := raw[0]
	sb := StagedBackup{ID: r.ID, Version: r.Version, Filename: r.Filename, Size: r.Size}
	if ms, err := strconv.ParseInt(r.Timestamp, 10, 64); err == nil && ms > 0 {
		sb.Time = time.UnixMilli(ms)
	}
	for _, site := range r.Sites {
		sb.Sites = append(sb.Sites, site.Name)
	}
	return sb, nil
}

// RestoreBackup replaces all of the Network application's settings with a
// backup staged by UploadBackup. The Network application then restarts:
// for about a minute its API is unavailable (routing and connected devices
// carry on). Requests made meanwhile fail; the Client logs in again once it
// is back.
func (c *Client) RestoreBackup(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("no staged backup ID")
	}
	var env classicEnvelope
	err := c.write(ctx, http.MethodPost, c.classic("/cmd/backup"), map[string]any{"cmd": "restore", "backup_id": id}, &env)
	c.mu.Lock()
	c.loggedIn = false // the restart ends the session
	c.mu.Unlock()
	return err
}
