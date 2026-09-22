package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// parseInterspersed parses flags that may appear before or after positional
// arguments (Go's flag package stops at the first positional otherwise).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals, nil
}

func firstPositional(p []string) string {
	if len(p) > 0 {
		return p[0]
	}
	return ""
}

func printProjectUsage() {
	fmt.Fprintln(os.Stderr, "scan7x project — persistent recon projects (stored in ~/.scan7x/scan7x.db)")
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintln(os.Stderr, "  scan7x project create <name> -target \"program\" [-platform hackerone] [-recon full]")
	fmt.Fprintln(os.Stderr, "  scan7x project update <name>            # re-scan; shows what's NEW since last time")
	fmt.Fprintln(os.Stderr, "  scan7x project list")
	fmt.Fprintln(os.Stderr, "  scan7x project show <name>")
	fmt.Fprintln(os.Stderr, "  scan7x project report <name> [-o dir]")
	fmt.Fprintln(os.Stderr, "  scan7x project delete <name>")
}

// runProject dispatches `scan7x project <sub> ...`.
func runProject(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printProjectUsage()
		return nil
	}
	store, err := OpenStore(os.Getenv("SCAN7X_DB"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	sub, rest := args[0], args[1:]
	switch sub {
	case "create", "add":
		return projectCreate(ctx, store, rest)
	case "update", "scan", "run":
		return projectUpdate(ctx, store, rest)
	case "list", "ls":
		return projectList(store)
	case "show", "info":
		return projectShow(store, rest)
	case "report":
		return projectReport(store, rest)
	case "delete", "rm":
		return projectDelete(store, rest)
	default:
		printProjectUsage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// reconOptions builds an options struct for a project flag set.
func projectFlags(name string) (*flag.FlagSet, *options, *string, *bool) {
	fs := flag.NewFlagSet("project "+name, flag.ContinueOnError)
	opt := &options{}
	fs.StringVar(&opt.platform, "platform", "all", "platform to search")
	target := fs.String("target", "", "program name/handle to search (defaults to the project name)")
	fs.StringVar(&opt.pull, "pull", "all", "scope categories to pull")
	fs.StringVar(&opt.recon, "recon", "full", "recon depth: scope|passive|full")
	fs.StringVar(&opt.sources, "sources", strings.Join(defaultSources, ","), "subdomain sources")
	fs.IntVar(&opt.pick, "pick", 0, "pick Nth match")
	fs.IntVar(&opt.threads, "threads", 25, "concurrency")
	fs.IntVar(&opt.timeout, "timeout", 15, "per-request timeout (s)")
	fs.IntVar(&opt.wbLimit, "wayback-limit", 20000, "max Wayback URLs per target")
	fs.StringVar(&opt.root, "root", "", "recon these root domains directly instead of a bounty program")
	refresh := fs.Bool("refresh", false, "force refresh of cached scope data")
	return fs, opt, target, refresh
}

// programFromRoots builds a synthetic program from raw wildcard roots so a
// project can track a domain that isn't (or isn't yet) a bounty program.
func programFromRoots(name, rootCSV string) Program {
	var assets []ScopeAsset
	for _, r := range splitCSV(rootCSV) {
		if h, _, ok := normalizeHost(r); ok {
			assets = append(assets, ScopeAsset{Identifier: "*." + h, RawType: "wildcard", Category: CatWildcard, Host: h, Wildcard: true})
		}
	}
	return Program{Platform: "manual", Name: name, Handle: slug(name), InScope: assets}
}

func projectCreate(ctx context.Context, store *Store, args []string) error {
	fs, opt, target, refresh := projectFlags("create")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	name := firstPositional(pos)
	if name == "" {
		return errors.New("usage: scan7x project create <name> -target \"program\"")
	}
	if _, err := store.GetProject(name); err == nil {
		return fmt.Errorf("project %q already exists — use 'scan7x project update %s'", name, name)
	}
	initHTTP(time.Duration(opt.timeout) * time.Second)

	var prog Program
	if strings.TrimSpace(opt.root) != "" {
		prog = programFromRoots(name, opt.root)
		if len(prog.InScope) == 0 {
			return errors.New("no valid root domains in -root")
		}
	} else {
		if strings.TrimSpace(*target) == "" {
			*target = name
		}
		if prog, err = findProgram(ctx, *opt, *target, *refresh); err != nil {
			return err
		}
	}
	if err := validateRecon(opt.recon); err != nil {
		return err
	}
	logf("[+] Program: %s [%s] %s", nonEmpty(prog.Name, prog.Handle), prog.Platform, prog.URL)

	if _, err := store.CreateProject(name, prog, opt.pull, opt.recon); err != nil {
		return fmt.Errorf("create project: %w", err)
	}
	selected, err := resolveCategories(opt.pull)
	if err != nil {
		return err
	}
	p, err := store.GetProject(name)
	if err != nil {
		return err
	}
	diff, res, err := runProjectScan(ctx, store, p, prog, *opt, selected)
	if res != nil {
		if res.Finished.IsZero() {
			res.Finished = time.Now()
		}
		_ = writeOutputs(res)
	}
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, col(cYellow, "  interrupted — progress saved; resume with: scan7x project update "+name))
			return nil
		}
		return err
	}
	fmt.Printf("\n%s created project %s\n", col(cBold+cGreen, "✓"), col(cBold+cWhite, name))
	printProjectDiff(diff, res, true)
	return nil
}

func projectUpdate(ctx context.Context, store *Store, args []string) error {
	fs, opt, _, refresh := projectFlags("update")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	name := firstPositional(pos)
	if name == "" {
		return errors.New("usage: scan7x project update <name>")
	}
	p, err := store.GetProject(name)
	if err != nil {
		return fmt.Errorf("project %q not found (create it first)", name)
	}
	initHTTP(time.Duration(opt.timeout) * time.Second)
	// Manual (root-based) projects use the stored scope. For real programs,
	// re-fetch so newly-added assets are detected, falling back to stored scope.
	var prog Program
	if p.Platform == "manual" {
		if prog, err = store.loadProgram(p); err != nil {
			return err
		}
	} else if prog, err = findProgramByHandle(ctx, p.Platform, p.Handle, *refresh); err != nil {
		logf("[warn] scope refresh failed (%v); using stored scope", err)
		if prog, err = store.loadProgram(p); err != nil {
			return err
		}
	}
	newAssets, err := store.syncAssets(p.ID, prog)
	if err != nil {
		return err
	}

	// A project keeps its configured recon depth and category selection.
	if err := validateRecon(nonEmpty(p.Recon, "full")); err != nil {
		return err
	}
	selected, err := resolveCategories(nonEmpty(p.Pull, "all"))
	if err != nil {
		return err
	}

	logf("[*] Updating project %s (%s) ...", name, prog.Handle)
	diff, res, err := runProjectScan(ctx, store, p, prog, *opt, selected)
	if res != nil {
		if res.Finished.IsZero() {
			res.Finished = time.Now()
		}
		_ = writeOutputs(res)
	}
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, col(cYellow, "  interrupted — progress saved; resume with: scan7x project update "+name))
			return nil
		}
		return err
	}
	diff.NewAssets = newAssets
	printProjectDiff(diff, res, false)
	return nil
}

func projectList(store *Store) error {
	items, err := store.ListProjects()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no projects yet — create one with: scan7x project create <name> -target \"program\"")
		return nil
	}
	fmt.Printf("%-20s %-11s %-22s %8s %6s %8s\n", "NAME", "PLATFORM", "HANDLE", "SUBDOMS", "LIVE", "SECRETS")
	for _, p := range items {
		sec := fmt.Sprint(p.Secrets)
		if p.Secrets > 0 {
			sec = col(cBold+cYellow, sec)
		}
		fmt.Printf("%-20s %-11s %-22s %8d %6d %8s\n",
			truncateStr(p.Name, 20), p.Platform, truncateStr(p.Handle, 22), p.Subdomains, p.Live, sec)
	}
	return nil
}

func projectShow(store *Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: scan7x project show <name>")
	}
	p, err := store.GetProject(args[0])
	if err != nil {
		return fmt.Errorf("project %q not found", args[0])
	}
	res, err := store.LoadResult(p)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", col(cBold+cWhite, p.Name), col(cGray, "["+p.Platform+"]"))
	fmt.Printf("  program : %s\n  handle  : %s\n  url     : %s\n  updated : %s\n\n",
		nonEmpty(p.ProgramName, "-"), p.Handle, nonEmpty(p.URL, "-"), p.Updated)
	fmt.Printf("  subdomains %d   resolved %d   live %d   endpoints %d   secrets %s\n",
		len(res.Subdomains), len(res.Resolved), len(res.LiveHosts), len(res.Endpoints),
		col(cBold+cYellow, fmt.Sprint(len(res.Secrets))))
	return nil
}

func projectReport(store *Store, args []string) error {
	fs := flag.NewFlagSet("project report", flag.ContinueOnError)
	out := fs.String("o", "", "output directory (default: the project directory)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	name := firstPositional(pos)
	if name == "" {
		return errors.New("usage: scan7x project report <name> [-o dir]")
	}
	p, err := store.GetProject(name)
	if err != nil {
		return fmt.Errorf("project %q not found", name)
	}
	res, err := store.LoadResult(p)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*out) != "" {
		res.OutDir = *out
	}
	if err := writeOutputs(res); err != nil {
		return err
	}
	fmt.Printf("%s report written to %s\n", col(cGreen, "✓"), col(cCyan, res.OutDir))
	return nil
}

func projectDelete(store *Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: scan7x project delete <name>")
	}
	name := args[0]
	if err := store.DeleteProject(name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("project %q not found", name)
		}
		return err
	}
	fmt.Printf("%s deleted project %s\n", col(cGreen, "✓"), name)
	return nil
}

// printProjectDiff renders what changed. On the first run everything is "new",
// so we show plain totals; on later runs we highlight the deltas.
func printProjectDiff(diff *Diff, res *ReconResult, first bool) {
	if first {
		fmt.Printf("  %s %d subdomains · %d live · %d endpoints · %s secrets\n",
			col(cDim, "stored:"), len(res.Subdomains), len(res.LiveHosts), len(res.Endpoints),
			col(cBold+cYellow, fmt.Sprint(len(res.Secrets))))
		fmt.Printf("  %s %s\n", col(cDim, "db:"), col(cCyan, nonEmpty(os.Getenv("SCAN7X_DB"), defaultDBPath())))
		return
	}
	if diff.Empty() {
		fmt.Printf("\n  %s no changes since last scan.\n", col(cGray, "○"))
		return
	}
	fmt.Printf("\n  %s\n", col(cBold+cGreen, "▲ NEW SINCE LAST SCAN"))
	if len(diff.NewAssets) > 0 {
		fmt.Printf("\n  %s (%d)\n", col(cBold+cMagenta, "NEW SCOPE ASSET"), len(diff.NewAssets))
		for _, a := range truncateList(diff.NewAssets, 30) {
			fmt.Printf("    %s %s\n", col(cMagenta, "+"), a)
		}
	}
	if len(diff.NewSubdomains) > 0 {
		fmt.Printf("\n  %s (%d)\n", col(cBold+cGreen, "NEW SUBDOMAIN"), len(diff.NewSubdomains))
		for _, h := range truncateList(diff.NewSubdomains, 30) {
			fmt.Printf("    %s %s\n", col(cGreen, "+"), h)
		}
		if len(diff.NewSubdomains) > 30 {
			fmt.Printf("    %s\n", col(cDim, fmt.Sprintf("… %d more", len(diff.NewSubdomains)-30)))
		}
	}
	if len(diff.NewLive) > 0 {
		fmt.Printf("\n  %s: %d\n", col(cBold+cCyan, "NEW LIVE HOST"), len(diff.NewLive))
	}
	if diff.NewEndpoints > 0 || diff.NewSecrets > 0 {
		fmt.Printf("\n  new endpoints: %d   new secrets: %s\n",
			diff.NewEndpoints, col(cBold+cYellow, fmt.Sprint(diff.NewSecrets)))
	}
	fmt.Println()
}

// scanStages are the resumable checkpoints of a full project scan.
var scanStages = []string{"enum", "probe", "js"}

func stageIndex(name string) int {
	for i, s := range scanStages {
		if s == name {
			return i
		}
	}
	return -1
}

// runProjectScan runs (or resumes) a staged, checkpointed scan and persists
// each stage to the database. If a previous run was interrupted, it continues
// from the next stage instead of redoing completed work.
func runProjectScan(ctx context.Context, store *Store, p *ProjectRow, prog Program, opt options, selected map[Category]bool) (*Diff, *ReconResult, error) {
	mode := nonEmpty(p.Recon, "full")
	roots := enumRoots(prog.InScope, selected)
	known := knownHosts(prog.InScope, selected)
	res := &ReconResult{
		Program: prog, OutDir: projectsDir(p.Name), Mode: mode,
		CatIDs: selectedCategoryIDs(prog, selected), Started: time.Now(),
		EnumPerSrc: map[string]int{}, Roots: roots, KnownHosts: known,
	}
	diff := &Diff{}

	// If the last run is still 'running', it was interrupted — resume it.
	resumeFrom, runID := 0, int64(0)
	if id, status, stage, ok := store.LastRun(p.ID); ok && status == "running" {
		runID = id
		if resumeFrom = stageIndex(stage) + 1; resumeFrom < 0 {
			resumeFrom = 0
		}
		if resumeFrom < len(scanStages) {
			logf("[*] %s", col(cBold+cYellow, fmt.Sprintf("resuming interrupted run — continuing from '%s'", scanStages[resumeFrom])))
		}
	}
	if runID == 0 {
		var err error
		if runID, err = store.StartRun(p.ID, mode); err != nil {
			return nil, nil, err
		}
	}
	cached := func(stage string) bool { return resumeFrom > stageIndex(stage) }
	finish := func() (*Diff, *ReconResult, error) {
		res.Finished = time.Now()
		_ = store.FinishRun(runID, res, len(diff.NewSubdomains))
		// reflect the full accumulated state so the report is complete.
		res.Endpoints = store.loadEndpoints(p.ID)
		res.Secrets = store.loadSecrets(p.ID)
		res.JSURLs = store.loadJSURLs(p.ID)
		return diff, res, nil
	}

	if mode == "scope" {
		return finish()
	}

	// STAGE 1 — enum: subdomains from sources + Wayback host extraction.
	if cached("enum") {
		res.Subdomains = store.loadSubdomains(p.ID)
		logf("[=] enum cached: %d subdomains", len(res.Subdomains))
	} else {
		logf("[*] enum: %d wildcard roots, %d explicit hosts", len(roots), len(known))
		var subs []string
		if len(roots) > 0 {
			merged, per, _ := enumerateAll(ctx, roots, splitCSV(opt.sources))
			subs, res.EnumPerSrc = merged, per
		}
		hostSet := append([]string{}, subs...)
		hostSet = append(hostSet, known...)
		res.AllURLs = collectURLs(ctx, roots, known, opt.wbLimit)
		for _, u := range res.AllURLs {
			if h := hostFromURL(u); h != "" && (inScopeAny(h, roots) || contains(known, h)) {
				hostSet = append(hostSet, h)
			}
		}
		res.Subdomains = dedupSorted(hostSet)
		newSubs, err := store.SaveSubdomains(p.ID, res.Subdomains)
		if err != nil {
			return nil, nil, err
		}
		diff.NewSubdomains = newSubs
		if ctx.Err() != nil {
			return diff, res, ctx.Err()
		}
		_ = store.CheckpointRun(runID, "enum")
	}

	if mode == "passive" {
		res.JSURLs = filterJSURLs(res.AllURLs)
		_ = store.SaveJSURLs(p.ID, res.JSURLs)
		return finish()
	}

	// STAGE 2 — probe: DNS resolution + live-host probing.
	if cached("probe") {
		res.Resolved = store.loadResolved(p.ID)
		res.LiveHosts = store.loadLiveHosts(p.ID)
		logf("[=] probe cached: %d live hosts", len(res.LiveHosts))
	} else {
		logf("[*] resolve %d subdomains ...", len(res.Subdomains))
		res.Resolved = resolveHosts(ctx, res.Subdomains, opt.threads*2)
		probeTargets := res.Subdomains
		if len(res.Resolved) > 0 {
			probeTargets = nil
			for _, r := range res.Resolved {
				probeTargets = append(probeTargets, r.Host)
			}
		}
		logf("[*] probe %d hosts ...", len(probeTargets))
		res.LiveHosts = probeHosts(ctx, probeTargets, opt.threads)
		_ = store.SaveResolved(p.ID, res.Resolved)
		newLive, err := store.SaveLiveHosts(p.ID, res.LiveHosts)
		if err != nil {
			return nil, nil, err
		}
		diff.NewLive = newLive
		if ctx.Err() != nil {
			return diff, res, ctx.Err()
		}
		_ = store.CheckpointRun(runID, "probe")
	}

	// STAGE 3 — js: discover JS URLs, download the new ones, extract.
	if len(res.AllURLs) == 0 && len(roots) > 0 {
		res.AllURLs = collectURLs(ctx, roots, known, opt.wbLimit)
	}
	var liveURLs []string
	for _, lh := range res.LiveHosts {
		liveURLs = append(liveURLs, lh.URL)
	}
	crawled := crawlScripts(ctx, liveURLs, opt.threads)
	candidates := dedupSorted(append(filterJSURLs(res.AllURLs), crawled...))
	var jsAll []string
	for _, u := range candidates {
		if h := hostFromURL(u); h != "" && (inScopeAny(h, roots) || contains(known, h)) {
			jsAll = append(jsAll, u)
		}
	}
	jsAll = dedupSorted(jsAll)
	already := store.jsURLSet(p.ID)
	var todo []string
	for _, u := range jsAll {
		if !already[u] {
			todo = append(todo, u)
		}
	}
	logf("[*] js: %d in-scope files (%d new to download) ...", len(jsAll), len(todo))
	res.JSDownloaded, res.Endpoints, res.Secrets = downloadAndExtract(ctx, todo, filepath.Join(res.OutDir, "js"), opt.threads)
	newEps, _ := store.SaveEndpoints(p.ID, res.Endpoints)
	newSecs, _ := store.SaveSecrets(p.ID, res.Secrets)
	_ = store.SaveJSURLs(p.ID, jsAll)
	diff.NewEndpoints, diff.NewSecrets = newEps, newSecs
	if ctx.Err() != nil {
		return diff, res, ctx.Err()
	}
	_ = store.CheckpointRun(runID, "js")
	return finish()
}

// --- program lookup helpers ---------------------------------------------

// findProgram searches platforms for a target and picks the best match.
func findProgram(ctx context.Context, opt options, target string, refresh bool) (Program, error) {
	platforms, err := resolvePlatforms(opt.platform)
	if err != nil {
		return Program{}, err
	}
	progs, err := searchPrograms(ctx, platforms, target, refresh)
	if err != nil {
		return Program{}, err
	}
	if len(progs) == 0 {
		return Program{}, fmt.Errorf("no program matched %q on %s", target, strings.Join(platforms, ","))
	}
	rankPrograms(progs, target)
	return chooseProgram(progs, opt, false, nil)
}

// findProgramByHandle re-fetches a specific program by its handle on a platform.
func findProgramByHandle(ctx context.Context, platform, handle string, refresh bool) (Program, error) {
	progs, err := searchPrograms(ctx, []string{platform}, handle, refresh)
	if err != nil {
		return Program{}, err
	}
	want := squash(handle)
	for _, p := range progs {
		if squash(p.Handle) == want {
			return p, nil
		}
	}
	if len(progs) > 0 {
		rankPrograms(progs, handle)
		return progs[0], nil
	}
	return Program{}, fmt.Errorf("program %q not found on %s", handle, platform)
}

var _ = time.Now // keep time imported if unused after edits
