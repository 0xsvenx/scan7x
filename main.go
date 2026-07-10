package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const version = "1.0.0"

type options struct {
	platform string
	target   string
	pull     string
	pick     int
	out      string
	recon    string
	sources  string
	root     string
	threads  int
	timeout  int
	wbLimit  int
	refresh  bool
	yes      bool
	noColor  bool
}

func main() {
	var opt options
	var showVersion bool

	flag.StringVar(&opt.platform, "platform", "all", "platform: hackerone|bugcrowd|intigriti|yeswehack|all")
	flag.StringVar(&opt.target, "target", "", "program name/handle to search (e.g. \"red bull\")")
	flag.StringVar(&opt.pull, "pull", "all", "scope categories: comma list of domains,wildcards,apis,mobile,cidr,source,other,all")
	flag.IntVar(&opt.pick, "pick", 0, "when several programs match, pick the Nth (1-based)")
	flag.StringVar(&opt.out, "o", "", "output directory (default ./output/<platform>_<handle>)")
	flag.StringVar(&opt.recon, "recon", "full", "recon depth: scope|passive|full")
	flag.StringVar(&opt.sources, "sources", strings.Join(defaultSources, ","), "subdomain sources (comma list)")
	flag.StringVar(&opt.root, "root", "", "skip scope lookup: run recon directly on these root domains (comma list)")
	flag.IntVar(&opt.threads, "threads", 25, "concurrency for probing/crawling/downloading")
	flag.IntVar(&opt.timeout, "timeout", 15, "per-request timeout (seconds) when touching targets")
	flag.IntVar(&opt.wbLimit, "wayback-limit", 20000, "max URLs per target from Wayback (0 = unlimited)")
	flag.BoolVar(&opt.refresh, "refresh", false, "force refresh of cached scope data")
	flag.BoolVar(&opt.yes, "y", false, "non-interactive: use flags/defaults, never prompt")
	flag.BoolVar(&opt.noColor, "no-color", false, "disable colored output")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "scan7x %s — pull bug-bounty scope, then recon it.\n\n", version)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  scan7x                                   # interactive wizard")
		fmt.Fprintln(os.Stderr, "  scan7x -target \"red bull\"                # search all platforms, full recon")
		fmt.Fprintln(os.Stderr, "  scan7x -platform hackerone -target uber -pull domains,wildcards -recon passive")
		fmt.Fprintln(os.Stderr, "  scan7x -root example.com -recon full     # skip scope lookup")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVersion {
		fmt.Println("scan7x " + version)
		return
	}

	setupColor(opt.noColor)
	initHTTP(time.Duration(opt.timeout) * time.Second)
	printBanner()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	if strings.TrimSpace(opt.root) != "" {
		err = runRootMode(ctx, opt)
	} else {
		err = runProgramMode(ctx, opt)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nerror: "+err.Error())
		os.Exit(1)
	}
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func runProgramMode(ctx context.Context, opt options) error {
	interactive := stdinIsTerminal() && opt.target == "" && !opt.yes
	reader := bufio.NewReader(os.Stdin)

	if interactive {
		opt.platform = promptPlatform(reader)
	}
	platforms, err := resolvePlatforms(opt.platform)
	if err != nil {
		return err
	}

	if interactive {
		opt.target = promptLine(reader, "Enter target program name (e.g. red bull): ", "")
	}
	if strings.TrimSpace(opt.target) == "" {
		return fmt.Errorf("no target given; use -target \"name\" or run interactively")
	}

	logf("[*] Searching %s for %q ...", strings.Join(platforms, ","), opt.target)
	progs, err := searchPrograms(ctx, platforms, opt.target, opt.refresh)
	if err != nil {
		return err
	}
	if len(progs) == 0 {
		return fmt.Errorf("no programs matched %q on %s", opt.target, strings.Join(platforms, ","))
	}
	rankPrograms(progs, opt.target)

	prog, err := chooseProgram(progs, opt, interactive, reader)
	if err != nil {
		return err
	}
	logf("[+] Selected: %s  [%s]  %s", nonEmpty(prog.Name, prog.Handle), prog.Platform, prog.URL)

	catIDs := categoryIdentifiers(prog)
	if interactive {
		opt.pull = promptCategories(reader, catIDs)
	}
	selected, err := resolveCategories(opt.pull)
	if err != nil {
		return err
	}
	if interactive {
		opt.recon = promptRecon(reader)
	}
	if err := validateRecon(opt.recon); err != nil {
		return err
	}
	return runPipeline(ctx, opt, prog, selected)
}

func runRootMode(ctx context.Context, opt options) error {
	var assets []ScopeAsset
	var roots []string
	for _, r := range splitCSV(opt.root) {
		h, _, ok := normalizeHost(r)
		if !ok {
			logf("[warn] skipping invalid root %q", r)
			continue
		}
		roots = append(roots, h)
		assets = append(assets, ScopeAsset{Identifier: "*." + h, RawType: "wildcard", Category: CatWildcard, Host: h, Wildcard: true})
	}
	if len(roots) == 0 {
		return fmt.Errorf("no valid root domains in -root")
	}
	if strings.TrimSpace(opt.recon) == "" {
		opt.recon = "full"
	}
	if err := validateRecon(opt.recon); err != nil {
		return err
	}
	prog := Program{Platform: "manual", Name: roots[0], Handle: slug(roots[0]), InScope: assets}
	sel := map[Category]bool{}
	for _, c := range allCategories {
		sel[c] = true
	}
	return runPipeline(ctx, opt, prog, sel)
}

func runPipeline(ctx context.Context, opt options, prog Program, selected map[Category]bool) error {
	mode := strings.ToLower(strings.TrimSpace(opt.recon))
	started := time.Now()

	outDir := opt.out
	if strings.TrimSpace(outDir) == "" {
		outDir = filepath.Join("output", safeDirName(prog))
	}

	res := &ReconResult{
		Program:    prog,
		OutDir:     outDir,
		Mode:       mode,
		CatIDs:     selectedCategoryIDs(prog, selected),
		Started:    started,
		EnumPerSrc: map[string]int{},
	}

	if mode != "scope" {
		roots := enumRoots(prog.InScope, selected)
		known := knownHosts(prog.InScope, selected)
		res.Roots = roots
		res.KnownHosts = known
		logf("[*] %d wildcard roots, %d explicit hosts", len(roots), len(known))

		var subs []string
		if len(roots) > 0 {
			logf("[*] Passive subdomain enumeration ...")
			merged, per, _ := enumerateAll(ctx, roots, splitCSV(opt.sources))
			subs, res.EnumPerSrc = merged, per
		}

		hostSet := append([]string{}, subs...)
		hostSet = append(hostSet, known...)

		logf("[*] Collecting URLs from Wayback ...")
		urls := collectURLs(ctx, roots, known, opt.wbLimit)
		res.AllURLs = urls
		for _, u := range urls {
			if h := hostFromURL(u); h != "" && (inScopeAny(h, roots) || contains(known, h)) {
				hostSet = append(hostSet, h)
			}
		}
		res.Subdomains = dedupSorted(hostSet)

		jsFromWayback := filterJSURLs(urls)

		if mode == "full" {
			logf("[*] Probing %d hosts (https/http) ...", len(res.Subdomains))
			res.LiveHosts = probeHosts(ctx, res.Subdomains, opt.threads)
			logf("[+] %d live hosts", len(res.LiveHosts))

			var liveURLs []string
			for _, lh := range res.LiveHosts {
				liveURLs = append(liveURLs, lh.URL)
			}
			logf("[*] Crawling live hosts for <script src> ...")
			crawled := crawlScripts(ctx, liveURLs, opt.threads)

			// keep only in-scope JS
			candidates := dedupSorted(append(append([]string{}, jsFromWayback...), crawled...))
			var jsAll []string
			for _, u := range candidates {
				if h := hostFromURL(u); h != "" && (inScopeAny(h, roots) || contains(known, h)) {
					jsAll = append(jsAll, u)
				}
			}
			res.JSURLs = dedupSorted(jsAll)

			logf("[*] Downloading %d JS files & extracting endpoints ...", len(res.JSURLs))
			res.JSDownloaded, res.Endpoints = downloadAndExtract(ctx, res.JSURLs, filepath.Join(outDir, "js"), opt.threads)
			logf("[+] Downloaded %d JS, extracted %d endpoints", len(res.JSDownloaded), len(res.Endpoints))
		} else {
			res.JSURLs = jsFromWayback
		}
	}

	res.Finished = time.Now()
	if err := writeOutputs(res); err != nil {
		return fmt.Errorf("writing outputs: %w", err)
	}
	printFinalSummary(res)
	return nil
}

// --- selection helpers ---------------------------------------------------

func chooseProgram(progs []Program, opt options, interactive bool, reader *bufio.Reader) (Program, error) {
	if len(progs) == 1 {
		return progs[0], nil
	}
	q := squash(opt.target)
	exact := -1
	for i, p := range progs {
		if squash(p.Handle) == q || squash(p.Name) == q {
			exact = i
			break
		}
	}
	if opt.pick > 0 {
		if opt.pick > len(progs) {
			return Program{}, fmt.Errorf("-pick %d out of range (%d matches)", opt.pick, len(progs))
		}
		return progs[opt.pick-1], nil
	}
	if !interactive {
		if exact >= 0 {
			return progs[exact], nil
		}
		printMatches(progs)
		return Program{}, fmt.Errorf("%d programs matched; re-run with -pick N or a more specific -target", len(progs))
	}
	printMatches(progs)
	for {
		s := promptLine(reader, fmt.Sprintf("Pick program [1-%d] (default 1): ", len(progs)), "1")
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= len(progs) {
			return progs[n-1], nil
		}
		fmt.Fprintln(os.Stderr, "invalid choice")
	}
}

func printMatches(progs []Program) {
	limit := len(progs)
	if limit > 25 {
		limit = 25
	}
	fmt.Fprintf(os.Stderr, "\nMatches (%d):\n", len(progs))
	for i := 0; i < limit; i++ {
		p := progs[i]
		fmt.Fprintf(os.Stderr, "  %2d) [%-9s] %-40s scope:%-4d %s\n",
			i+1, p.Platform, truncateStr(nonEmpty(p.Name, p.Handle), 40), len(p.InScope), p.URL)
	}
	if len(progs) > limit {
		fmt.Fprintf(os.Stderr, "  ... and %d more (refine -target)\n", len(progs)-limit)
	}
	fmt.Fprintln(os.Stderr)
}

func resolvePlatforms(p string) ([]string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" || p == "all" {
		return platformOrder, nil
	}
	var out []string
	for _, part := range splitCSV(p) {
		if _, ok := platformFiles[part]; !ok {
			return nil, fmt.Errorf("unknown platform %q (hackerone|bugcrowd|intigriti|yeswehack|all)", part)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return platformOrder, nil
	}
	return out, nil
}

func resolveCategories(pull string) (map[Category]bool, error) {
	pull = strings.ToLower(strings.TrimSpace(pull))
	sel := map[Category]bool{}
	selectAll := func() {
		for _, c := range allCategories {
			sel[c] = true
		}
	}
	if pull == "" || pull == "all" {
		selectAll()
		return sel, nil
	}
	aliases := map[string]Category{
		"domains": CatDomain, "domain": CatDomain,
		"wildcards": CatWildcard, "wildcard": CatWildcard,
		"apis": CatAPI, "api": CatAPI,
		"mobile": CatMobile,
		"cidr":   CatCIDR,
		"source": CatSource,
		"other":  CatOther,
	}
	for _, part := range splitCSV(pull) {
		if part == "all" {
			selectAll()
			continue
		}
		c, ok := aliases[part]
		if !ok {
			return nil, fmt.Errorf("unknown category %q", part)
		}
		sel[c] = true
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("no valid categories selected")
	}
	return sel, nil
}

func validateRecon(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "scope", "passive", "full":
		return nil
	}
	return fmt.Errorf("invalid -recon %q (use scope|passive|full)", mode)
}

func safeDirName(p Program) string {
	base := slug(nonEmpty(p.Handle, p.Name))
	if base == "" {
		base = "target"
	}
	return p.Platform + "_" + base
}

func selectedCategoryIDs(p Program, sel map[Category]bool) map[Category][]string {
	out := map[Category][]string{}
	for c, ids := range categoryIdentifiers(p) {
		if sel[c] {
			out[c] = ids
		}
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func inScopeAny(host string, roots []string) bool {
	host = strings.ToLower(host)
	for _, r := range roots {
		r = strings.ToLower(r)
		if host == r || strings.HasSuffix(host, "."+r) {
			return true
		}
	}
	return false
}

func printFinalSummary(res *ReconResult) {
	bar := col(cCyan, "│")
	rule := "  " + col(cCyan, strings.Repeat("─", 52))
	num := func(n int) string { return col(cBold+cWhite, fmt.Sprint(n)) }
	row := func(label, val string) {
		fmt.Printf("  %s %s %s\n", bar, col(cDim, fmt.Sprintf("%-10s", label)), val)
	}
	fmt.Println()
	fmt.Println("  " + col(cBold+cGreen, "✓ recon complete"))
	fmt.Println(rule)
	row("program", col(cWhite, nonEmpty(res.Program.Name, res.Program.Handle))+"  "+col(cMagenta, "["+res.Program.Platform+"]"))
	row("scope", num(len(res.Program.InScope))+col(cDim, " in-scope assets"))
	if res.Mode != "scope" {
		row("discovery", fmt.Sprintf("%s subdomains  %s live  %s urls",
			num(len(res.Subdomains)), num(len(res.LiveHosts)), num(len(res.AllURLs))))
		row("javascript", fmt.Sprintf("%s files  %s endpoints",
			num(len(res.JSURLs)), num(len(res.Endpoints))))
	}
	row("output", col(cCyan, res.OutDir))
	row("report", col(cCyan, filepath.Join(res.OutDir, "report.md")))
	fmt.Println(rule)
}

// --- interactive prompts -------------------------------------------------

func promptLine(r *bufio.Reader, prompt, def string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := r.ReadString('\n')
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}

func promptPlatform(r *bufio.Reader) string {
	opts := []string{"all", "hackerone", "bugcrowd", "intigriti", "yeswehack"}
	fmt.Fprintln(os.Stderr, "Select platform:")
	for i, o := range opts {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, o)
	}
	s := promptLine(r, "Choice [1]: ", "1")
	if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(opts) {
		return opts[n-1]
	}
	s = strings.ToLower(s)
	for _, o := range opts {
		if o == s {
			return o
		}
	}
	return "all"
}

func promptCategories(r *bufio.Reader, catIDs map[Category][]string) string {
	fmt.Fprintln(os.Stderr, "\nScope found:")
	for _, c := range allCategories {
		if n := len(catIDs[c]); n > 0 {
			fmt.Fprintf(os.Stderr, "   - %-10s %d\n", c, n)
		}
	}
	fmt.Fprintln(os.Stderr, "What to pull? comma list (domains,apis,wildcards,...) or 'all'")
	return promptLine(r, "Choice [all]: ", "all")
}

func promptRecon(r *bufio.Reader) string {
	fmt.Fprintln(os.Stderr, "\nRecon depth:")
	fmt.Fprintln(os.Stderr, "  1) scope    — only download & categorize scope")
	fmt.Fprintln(os.Stderr, "  2) passive  — scope + passive subdomain enum + Wayback JS list")
	fmt.Fprintln(os.Stderr, "  3) full     — enum + live probe + crawl + download JS + endpoints")
	switch promptLine(r, "Choice [3]: ", "3") {
	case "1", "scope":
		return "scope"
	case "2", "passive":
		return "passive"
	default:
		return "full"
	}
}
