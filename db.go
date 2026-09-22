package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed persistence layer for projects and their findings.
type Store struct {
	db *sql.DB
}

// scan7xHome is the base directory for the database and project artifacts.
// Override with SCAN7X_HOME (useful for isolation and tests).
func scan7xHome() string {
	if h := os.Getenv("SCAN7X_HOME"); strings.TrimSpace(h) != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".scan7x")
}

func defaultDBPath() string { return filepath.Join(scan7xHome(), "scan7x.db") }

// projectsDir is where per-project artifacts (JS files, generated reports) live.
func projectsDir(name string) string {
	return filepath.Join(scan7xHome(), "projects", slug(name))
}

const schema = `
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  program_name TEXT, platform TEXT, handle TEXT, url TEXT,
  pull TEXT, recon TEXT,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  project_id INTEGER, category TEXT, identifier TEXT,
  first_seen TEXT,
  PRIMARY KEY (project_id, category, identifier)
);
CREATE TABLE IF NOT EXISTS subdomains (
  project_id INTEGER, host TEXT, resolved INTEGER DEFAULT 0, ips TEXT,
  first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (project_id, host)
);
CREATE TABLE IF NOT EXISTS live_hosts (
  project_id INTEGER, url TEXT, status INTEGER, server TEXT, title TEXT,
  first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (project_id, url)
);
CREATE TABLE IF NOT EXISTS endpoints (
  project_id INTEGER, endpoint TEXT, first_seen TEXT,
  PRIMARY KEY (project_id, endpoint)
);
CREATE TABLE IF NOT EXISTS secrets (
  project_id INTEGER, type TEXT, match TEXT, first_seen TEXT,
  PRIMARY KEY (project_id, type, match)
);
CREATE TABLE IF NOT EXISTS js_files (
  project_id INTEGER, url TEXT, first_seen TEXT,
  PRIMARY KEY (project_id, url)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, mode TEXT,
  status TEXT, stage TEXT,
  started_at TEXT, finished_at TEXT,
  subdomains INTEGER, resolved INTEGER, live INTEGER, urls INTEGER,
  js INTEGER, endpoints INTEGER, secrets INTEGER, new_subdomains INTEGER
);
`

// migrations are best-effort ALTERs for databases created by earlier builds;
// they error harmlessly ("duplicate column") when already applied.
var migrations = []string{
	`ALTER TABLE runs ADD COLUMN status TEXT`,
	`ALTER TABLE runs ADD COLUMN stage TEXT`,
}

// OpenStore opens (creating if needed) the SQLite database and applies the schema.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		path = defaultDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialize access; avoids "database is locked"
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	for _, m := range migrations {
		_, _ = db.Exec(m)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

// ProjectRow is a stored project.
type ProjectRow struct {
	ID                                                    int64
	Name, ProgramName, Platform, Handle, URL, Pull, Recon string
	Created, Updated                                      string
}

// ProjectSummary is a compact row for `project list`.
type ProjectSummary struct {
	Name, Platform, Handle, Updated string
	Subdomains, Live, Secrets       int
}

// Diff captures what a run discovered that the project had not seen before.
type Diff struct {
	NewAssets     []string
	NewSubdomains []string
	NewLive       []string
	NewEndpoints  int
	NewSecrets    int
}

func (d *Diff) Empty() bool {
	return len(d.NewAssets) == 0 && len(d.NewSubdomains) == 0 && len(d.NewLive) == 0 &&
		d.NewEndpoints == 0 && d.NewSecrets == 0
}

// CreateProject inserts a new project and its scope assets.
func (s *Store) CreateProject(name string, p Program, pull, recon string) (int64, error) {
	now := nowStr()
	r, err := s.db.Exec(`INSERT INTO projects(name,program_name,platform,handle,url,pull,recon,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, name, p.Name, p.Platform, p.Handle, p.URL, pull, recon, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := r.LastInsertId()
	for _, a := range p.InScope {
		_, _ = s.db.Exec(`INSERT OR IGNORE INTO assets(project_id,category,identifier,first_seen) VALUES(?,?,?,?)`,
			id, string(a.Category), a.Identifier, now)
	}
	return id, nil
}

func (s *Store) GetProject(name string) (*ProjectRow, error) {
	var p ProjectRow
	err := s.db.QueryRow(`SELECT id,name,program_name,platform,handle,url,pull,recon,created_at,updated_at
		FROM projects WHERE name=?`, name).Scan(
		&p.ID, &p.Name, &p.ProgramName, &p.Platform, &p.Handle, &p.URL, &p.Pull, &p.Recon, &p.Created, &p.Updated)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects() ([]ProjectSummary, error) {
	rows, err := s.db.Query(`SELECT p.name,p.platform,p.handle,p.updated_at,
		(SELECT COUNT(*) FROM subdomains WHERE project_id=p.id),
		(SELECT COUNT(*) FROM live_hosts WHERE project_id=p.id),
		(SELECT COUNT(*) FROM secrets WHERE project_id=p.id)
		FROM projects p ORDER BY p.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectSummary
	for rows.Next() {
		var s ProjectSummary
		if err := rows.Scan(&s.Name, &s.Platform, &s.Handle, &s.Updated, &s.Subdomains, &s.Live, &s.Secrets); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) DeleteProject(name string) error {
	p, err := s.GetProject(name)
	if err != nil {
		return err
	}
	for _, t := range []string{"assets", "subdomains", "live_hosts", "endpoints", "secrets", "js_files", "runs"} {
		if _, err := s.db.Exec("DELETE FROM "+t+" WHERE project_id=?", p.ID); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`DELETE FROM projects WHERE id=?`, p.ID)
	return err
}

// loadProgram rebuilds a Program (including in-scope assets) from stored rows,
// so an update can re-run recon without another scope lookup if desired.
func (s *Store) loadProgram(p *ProjectRow) (Program, error) {
	prog := Program{Platform: p.Platform, Name: p.ProgramName, Handle: p.Handle, URL: p.URL}
	rows, err := s.db.Query(`SELECT category,identifier FROM assets WHERE project_id=?`, p.ID)
	if err != nil {
		return prog, err
	}
	defer rows.Close()
	for rows.Next() {
		var cat, id string
		if err := rows.Scan(&cat, &id); err != nil {
			return prog, err
		}
		host, wild, _ := normalizeHost(id)
		prog.InScope = append(prog.InScope, ScopeAsset{Identifier: id, Category: Category(cat), Host: host, Wildcard: wild})
	}
	return prog, rows.Err()
}

// syncAssets stores any newly-added scope assets and returns the new identifiers
// (this is how "Bugcrowd added a new domain" is detected).
func (s *Store) syncAssets(projectID int64, prog Program) ([]string, error) {
	now := nowStr()
	var added []string
	for _, a := range prog.InScope {
		r, err := s.db.Exec(`INSERT OR IGNORE INTO assets(project_id,category,identifier,first_seen) VALUES(?,?,?,?)`,
			projectID, string(a.Category), a.Identifier, now)
		if err != nil {
			return added, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			added = append(added, a.Identifier)
		}
	}
	return dedupSorted(added), nil
}

// --- granular persistence (each returns what was new) --------------------

func (s *Store) SaveSubdomains(projectID int64, subs []string) ([]string, error) {
	now := nowStr()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var fresh []string
	for _, h := range subs {
		r, err := tx.Exec(`INSERT OR IGNORE INTO subdomains(project_id,host,first_seen,last_seen) VALUES(?,?,?,?)`, projectID, h, now, now)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			fresh = append(fresh, h)
		} else {
			_, _ = tx.Exec(`UPDATE subdomains SET last_seen=? WHERE project_id=? AND host=?`, now, projectID, h)
		}
	}
	return fresh, tx.Commit()
}

func (s *Store) SaveResolved(projectID int64, resolved []ResolvedHost) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, rh := range resolved {
		_, _ = tx.Exec(`UPDATE subdomains SET resolved=1, ips=? WHERE project_id=? AND host=?`, strings.Join(rh.IPs, ","), projectID, rh.Host)
	}
	return tx.Commit()
}

func (s *Store) SaveLiveHosts(projectID int64, live []LiveHost) ([]string, error) {
	now := nowStr()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var fresh []string
	for _, lh := range live {
		r, err := tx.Exec(`INSERT OR IGNORE INTO live_hosts(project_id,url,status,server,title,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
			projectID, lh.URL, lh.Status, lh.Server, lh.Title, now, now)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			fresh = append(fresh, lh.URL)
		} else {
			_, _ = tx.Exec(`UPDATE live_hosts SET status=?,server=?,title=?,last_seen=? WHERE project_id=? AND url=?`, lh.Status, lh.Server, lh.Title, now, projectID, lh.URL)
		}
	}
	return fresh, tx.Commit()
}

func (s *Store) saveCounted(projectID int64, items []string, insert func(*sql.Tx, string) (int64, error)) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, it := range items {
		affected, err := insert(tx, it)
		if err != nil {
			return 0, err
		}
		if affected > 0 {
			n++
		}
	}
	return n, tx.Commit()
}

func (s *Store) SaveEndpoints(projectID int64, eps []string) (int, error) {
	now := nowStr()
	return s.saveCounted(projectID, eps, func(tx *sql.Tx, e string) (int64, error) {
		r, err := tx.Exec(`INSERT OR IGNORE INTO endpoints(project_id,endpoint,first_seen) VALUES(?,?,?)`, projectID, e, now)
		if err != nil {
			return 0, err
		}
		a, _ := r.RowsAffected()
		return a, nil
	})
}

func (s *Store) SaveSecrets(projectID int64, secs []Secret) (int, error) {
	now := nowStr()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, sec := range secs {
		r, err := tx.Exec(`INSERT OR IGNORE INTO secrets(project_id,type,match,first_seen) VALUES(?,?,?,?)`, projectID, sec.Type, sec.Match, now)
		if err != nil {
			return 0, err
		}
		if a, _ := r.RowsAffected(); a > 0 {
			n++
		}
	}
	return n, tx.Commit()
}

func (s *Store) SaveJSURLs(projectID int64, urls []string) error {
	now := nowStr()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, u := range urls {
		_, _ = tx.Exec(`INSERT OR IGNORE INTO js_files(project_id,url,first_seen) VALUES(?,?,?)`, projectID, u, now)
	}
	return tx.Commit()
}

// SaveResult persists a full result in one shot and returns the diff.
func (s *Store) SaveResult(projectID int64, res *ReconResult) (*Diff, error) {
	diff := &Diff{}
	var err error
	if diff.NewSubdomains, err = s.SaveSubdomains(projectID, res.Subdomains); err != nil {
		return nil, err
	}
	if err = s.SaveResolved(projectID, res.Resolved); err != nil {
		return nil, err
	}
	if diff.NewLive, err = s.SaveLiveHosts(projectID, res.LiveHosts); err != nil {
		return nil, err
	}
	if diff.NewEndpoints, err = s.SaveEndpoints(projectID, res.Endpoints); err != nil {
		return nil, err
	}
	if diff.NewSecrets, err = s.SaveSecrets(projectID, res.Secrets); err != nil {
		return nil, err
	}
	if err = s.SaveJSURLs(projectID, res.JSURLs); err != nil {
		return nil, err
	}
	id, _ := s.StartRun(projectID, res.Mode)
	_ = s.FinishRun(id, res, len(diff.NewSubdomains))
	_, _ = s.db.Exec(`UPDATE projects SET updated_at=? WHERE id=?`, nowStr(), projectID)
	return diff, nil
}

// --- run lifecycle (smart resume) ----------------------------------------

func (s *Store) StartRun(projectID int64, mode string) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO runs(project_id,mode,status,stage,started_at) VALUES(?,?,?,?,?)`,
		projectID, mode, "running", "", nowStr())
	if err != nil {
		return 0, err
	}
	id, _ := r.LastInsertId()
	return id, nil
}

func (s *Store) CheckpointRun(runID int64, stage string) error {
	_, err := s.db.Exec(`UPDATE runs SET stage=? WHERE id=?`, stage, runID)
	return err
}

func (s *Store) FinishRun(runID int64, res *ReconResult, newSubs int) error {
	_, err := s.db.Exec(`UPDATE runs SET status=?, stage=?, finished_at=?,
		subdomains=?, resolved=?, live=?, urls=?, js=?, endpoints=?, secrets=?, new_subdomains=? WHERE id=?`,
		"completed", "done", nowStr(),
		len(res.Subdomains), len(res.Resolved), len(res.LiveHosts), len(res.AllURLs),
		len(res.JSURLs), len(res.Endpoints), len(res.Secrets), newSubs, runID)
	return err
}

// LastRun returns the most recent run's id, status and last-completed stage.
func (s *Store) LastRun(projectID int64) (id int64, status, stage string, ok bool) {
	var st, sg sql.NullString
	err := s.db.QueryRow(`SELECT id,COALESCE(status,''),COALESCE(stage,'') FROM runs WHERE project_id=? ORDER BY id DESC LIMIT 1`, projectID).Scan(&id, &st, &sg)
	if err != nil {
		return 0, "", "", false
	}
	return id, st.String, sg.String, true
}

// --- loaders for resume --------------------------------------------------

func (s *Store) loadStrings(query string, projectID int64) []string {
	rows, err := s.db.Query(query, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func (s *Store) loadSubdomains(projectID int64) []string {
	return s.loadStrings(`SELECT host FROM subdomains WHERE project_id=? ORDER BY host`, projectID)
}

func (s *Store) loadResolved(projectID int64) []ResolvedHost {
	rows, err := s.db.Query(`SELECT host,COALESCE(ips,'') FROM subdomains WHERE project_id=? AND resolved=1 ORDER BY host`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ResolvedHost
	for rows.Next() {
		var host, ips string
		if rows.Scan(&host, &ips) == nil {
			var list []string
			if ips != "" {
				list = strings.Split(ips, ",")
			}
			out = append(out, ResolvedHost{Host: host, IPs: list})
		}
	}
	return out
}

func (s *Store) loadLiveHosts(projectID int64) []LiveHost {
	rows, err := s.db.Query(`SELECT url,status,COALESCE(server,''),COALESCE(title,'') FROM live_hosts WHERE project_id=? ORDER BY url`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []LiveHost
	for rows.Next() {
		var lh LiveHost
		if rows.Scan(&lh.URL, &lh.Status, &lh.Server, &lh.Title) == nil {
			out = append(out, lh)
		}
	}
	return out
}

func (s *Store) loadJSURLs(projectID int64) []string {
	return s.loadStrings(`SELECT url FROM js_files WHERE project_id=? ORDER BY url`, projectID)
}

func (s *Store) loadEndpoints(projectID int64) []string {
	return s.loadStrings(`SELECT endpoint FROM endpoints WHERE project_id=? ORDER BY endpoint`, projectID)
}

func (s *Store) loadSecrets(projectID int64) []Secret {
	rows, err := s.db.Query(`SELECT type,match FROM secrets WHERE project_id=? ORDER BY type`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var sec Secret
		if rows.Scan(&sec.Type, &sec.Match) == nil {
			out = append(out, sec)
		}
	}
	return out
}

func (s *Store) jsURLSet(projectID int64) map[string]bool {
	set := map[string]bool{}
	for _, u := range s.loadJSURLs(projectID) {
		set[u] = true
	}
	return set
}

// LoadResult reconstructs a ReconResult from stored rows so `project report`
// can render a report from the accumulated database state.
func (s *Store) LoadResult(p *ProjectRow) (*ReconResult, error) {
	prog, err := s.loadProgram(p)
	if err != nil {
		return nil, err
	}
	res := &ReconResult{Program: prog, Mode: nonEmpty(p.Recon, "full"), OutDir: projectsDir(p.Name), CatIDs: map[Category][]string{}, EnumPerSrc: map[string]int{}}
	for _, a := range prog.InScope {
		res.CatIDs[a.Category] = append(res.CatIDs[a.Category], a.Identifier)
	}
	scan := func(q string, fn func(*sql.Rows) error) error {
		rows, err := s.db.Query(q, p.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := fn(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	_ = scan(`SELECT host,resolved,COALESCE(ips,'') FROM subdomains WHERE project_id=? ORDER BY host`, func(r *sql.Rows) error {
		var host, ips string
		var resolved int
		if err := r.Scan(&host, &resolved, &ips); err != nil {
			return err
		}
		res.Subdomains = append(res.Subdomains, host)
		if resolved == 1 {
			var list []string
			if ips != "" {
				list = strings.Split(ips, ",")
			}
			res.Resolved = append(res.Resolved, ResolvedHost{Host: host, IPs: list})
		}
		return nil
	})
	_ = scan(`SELECT url,status,server,title FROM live_hosts WHERE project_id=? ORDER BY url`, func(r *sql.Rows) error {
		var lh LiveHost
		if err := r.Scan(&lh.URL, &lh.Status, &lh.Server, &lh.Title); err != nil {
			return err
		}
		res.LiveHosts = append(res.LiveHosts, lh)
		return nil
	})
	_ = scan(`SELECT endpoint FROM endpoints WHERE project_id=? ORDER BY endpoint`, func(r *sql.Rows) error {
		var e string
		if err := r.Scan(&e); err != nil {
			return err
		}
		res.Endpoints = append(res.Endpoints, e)
		return nil
	})
	_ = scan(`SELECT type,match FROM secrets WHERE project_id=? ORDER BY type`, func(r *sql.Rows) error {
		var sec Secret
		if err := r.Scan(&sec.Type, &sec.Match); err != nil {
			return err
		}
		res.Secrets = append(res.Secrets, sec)
		return nil
	})
	_ = scan(`SELECT url FROM js_files WHERE project_id=? ORDER BY url`, func(r *sql.Rows) error {
		var u string
		if err := r.Scan(&u); err != nil {
			return err
		}
		res.JSURLs = append(res.JSURLs, u)
		return nil
	})
	res.Started, res.Finished = time.Now(), time.Now()
	return res, nil
}
