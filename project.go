package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
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
	refresh := fs.Bool("refresh", false, "force refresh of cached scope data")
	return fs, opt, target, refresh
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
	if strings.TrimSpace(*target) == "" {
		*target = name
	}
	initHTTP(time.Duration(opt.timeout) * time.Second)

	prog, err := findProgram(ctx, *opt, *target, *refresh)
	if err != nil {
		return err
	}
	if err := validateRecon(opt.recon); err != nil {
		return err
	}
	logf("[+] Program: %s [%s] %s", nonEmpty(prog.Name, prog.Handle), prog.Platform, prog.URL)

	id, err := store.CreateProject(name, prog, opt.pull, opt.recon)
	if err != nil {
		return fmt.Errorf("create project: %w", err)
	}
	selected, err := resolveCategories(opt.pull)
	if err != nil {
		return err
	}
	res := computeRecon(ctx, *opt, prog, selected, projectsDir(name))
	diff, err := store.SaveResult(id, res)
	if err != nil {
		return fmt.Errorf("save results: %w", err)
	}
	_ = writeOutputs(res)
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
	// Prefer freshly-fetched scope so newly-added program assets are detected;
	// fall back to the stored scope if the lookup fails.
	prog, ferr := findProgramByHandle(ctx, p.Platform, p.Handle, *refresh)
	if ferr != nil {
		logf("[warn] scope refresh failed (%v); using stored scope", ferr)
		if prog, err = store.loadProgram(p); err != nil {
			return err
		}
	}
	newAssets, err := store.syncAssets(p.ID, prog)
	if err != nil {
		return err
	}

	// A project keeps its configured recon depth and category selection.
	opt.recon = nonEmpty(p.Recon, "full")
	if err := validateRecon(opt.recon); err != nil {
		return err
	}
	selected, err := resolveCategories(nonEmpty(p.Pull, "all"))
	if err != nil {
		return err
	}

	logf("[*] Updating project %s (%s) ...", name, prog.Handle)
	res := computeRecon(ctx, *opt, prog, selected, projectsDir(name))
	diff, err := store.SaveResult(p.ID, res)
	if err != nil {
		return fmt.Errorf("save results: %w", err)
	}
	diff.NewAssets = newAssets
	_ = writeOutputs(res)
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
