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

// version and commit are overridable at build time via -ldflags
// "-X main.version=... -X main.commit=...".
var (
	version = "1.1.0"
	commit  = "dev"
)

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
	silent   bool
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
	flag.BoolVar(&opt.silent, "silent", false, "suppress banner and progress (quiet mode)")
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
		fmt.Printf("scan7x %s (%s)\n", version, commit)
		return
	}

	silent = opt.silent
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
	// Interactive when stdin is a terminal (or SCAN7X_INTERACTIVE=1 to drive the
	// wizard from piped input) and no target was given on the command line.
	interactive := (stdinIsTerminal() || os.Getenv("SCAN7X_INTERACTIVE") == "1") && opt.target == "" && !opt.yes
	reader := bufio.NewReader(os.Stdin)

	if interactive {
		fmt.Fprintln(os.Stderr, col(cDim, "  tip: type 'exit' at any prompt to quit"))
	}

	// Each iteration handles one program end-to-end. In interactive mode we
	// loop so a wrong entry re-asks instead of dropping out of the tool, and
	// the user can change platform, scan another program, or type 'exit'.
	first := true
	for {
		if interactive {
			if first || promptYesNo(reader, "\nChange platform? [y/N]: ", false) {
				opt.platform = promptPlatform(reader)
			}
		}
		first = false
		platforms, err := resolvePlatforms(opt.platform)
		if err != nil {
			return err
		}

		var prog Program
		if interactive {
			prog = interactiveSelectProgram(ctx, opt, platforms, reader)
		} else {
			if strings.TrimSpace(opt.target) == "" {
				return fmt.Errorf("no target given; use -target \"name\" or run interactively")
			}
			logf("[*] Searching %s for %q ...", strings.Join(platforms, ","), opt.target)
			progs, serr := searchPrograms(ctx, platforms, opt.target, opt.refresh)
			if serr != nil {
				return serr
			}
			if len(progs) == 0 {
				return fmt.Errorf("no programs matched %q on %s", opt.target, strings.Join(platforms, ","))
			}
			rankPrograms(progs, opt.target)
			prog, err = chooseProgram(progs, opt, false, reader)
			if err != nil {
				return err
			}
		}
		logf("[+] Selected: %s  [%s]  %s", nonEmpty(prog.Name, prog.Handle), prog.Platform, prog.URL)

		catIDs := categoryIdentifiers(prog)
		var selected map[Category]bool
		if interactive {
			selected = promptCategoriesMenu(reader, catIDs)
			opt.recon = promptRecon(reader)
		} else {
			if selected, err = resolveCategories(opt.pull); err != nil {
				return err
			}
		}
		if err := validateRecon(opt.recon); err != nil {
			return err
		}

		if perr := runPipeline(ctx, opt, prog, selected); perr != nil {
			if !interactive {
				return perr
			}
			fmt.Fprintln(os.Stderr, col(cRed, "  run failed: "+perr.Error()+" — you can try another program"))
		}

		if !interactive {
			return nil
		}
		if !promptYesNo(reader, "\nScan another program? [Y/n]: ", true) {
			quitNow()
		}
		opt.target, opt.pull = "", "all"
	}
}

// interactiveSelectProgram prompts for a program name and keeps re-asking when
// the search errors or finds nothing, so a typo never kicks the user out.
func interactiveSelectProgram(ctx context.Context, opt options, platforms []string, reader *bufio.Reader) Program {
	for {
		target := promptLine(reader, "Enter target program name (e.g. red bull), or 'exit': ", "")
		if target == "" {
			fmt.Fprintln(os.Stderr, col(cYellow, "  type a program name, or 'exit' to quit"))
			continue
		}
		logf("[*] Searching %s for %q ...", strings.Join(platforms, ","), target)
		progs, err := searchPrograms(ctx, platforms, target, opt.refresh)
		if err != nil {
			fmt.Fprintln(os.Stderr, col(cYellow, "  search failed: "+err.Error()+" — try again"))
			continue
		}
		if len(progs) == 0 {
			fmt.Fprintln(os.Stderr, col(cYellow, fmt.Sprintf("  no program matched %q — try another name", target)))
			continue
		}
		rankPrograms(progs, target)
		optCopy := opt
		optCopy.target = target
		prog, err := chooseProgram(progs, optCopy, true, reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, col(cYellow, "  "+err.Error()+" — try again"))
			continue
		}
		return prog
	}
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
			logf("[*] Resolving %d subdomains (DNS) ...", len(res.Subdomains))
			res.Resolved = resolveHosts(ctx, res.Subdomains, opt.threads*2)
			logf("[+] %d resolve", len(res.Resolved))

			probeTargets := res.Subdomains
			if len(res.Resolved) > 0 {
				probeTargets = nil
				for _, r := range res.Resolved {
					probeTargets = append(probeTargets, r.Host)
				}
			}
			logf("[*] Probing %d hosts (https/http) ...", len(probeTargets))
			res.LiveHosts = probeHosts(ctx, probeTargets, opt.threads)
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

			logf("[*] Downloading %d JS files, extracting endpoints & secrets ...", len(res.JSURLs))
			res.JSDownloaded, res.Endpoints, res.Secrets = downloadAndExtract(ctx, res.JSURLs, filepath.Join(outDir, "js"), opt.threads)
			logf("[+] Downloaded %d JS, %d endpoints, %d secrets", len(res.JSDownloaded), len(res.Endpoints), len(res.Secrets))
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
		row("discovery", fmt.Sprintf("%s subdomains  %s resolve  %s live  %s urls",
			num(len(res.Subdomains)), num(len(res.Resolved)), num(len(res.LiveHosts)), num(len(res.AllURLs))))
		js := fmt.Sprintf("%s files  %s endpoints", num(len(res.JSURLs)), num(len(res.Endpoints)))
		if len(res.Secrets) > 0 {
			js += "  " + col(cBold+cYellow, fmt.Sprintf("%d secrets ⚠", len(res.Secrets)))
		}
		row("javascript", js)
	}
	row("output", col(cCyan, res.OutDir))
	row("report", col(cCyan, filepath.Join(res.OutDir, "report.md")))
	fmt.Println(rule)
}

// --- interactive prompts -------------------------------------------------

func isQuit(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "exit", "quit", "q":
		return true
	}
	return false
}

// quitNow prints a friendly goodbye and exits cleanly (status 0).
func quitNow() {
	fmt.Fprintln(os.Stderr, col(cGray, "\nbye — happy hunting."))
	os.Exit(0)
}

func promptLine(r *bufio.Reader, prompt, def string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		quitNow() // EOF / Ctrl+D / closed stdin
	}
	line = strings.TrimSpace(line)
	if isQuit(line) {
		quitNow()
	}
	if line != "" {
		return line
	}
	return def
}

// promptYesNo asks a yes/no question; def is the answer used for empty input.
func promptYesNo(r *bufio.Reader, prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	switch strings.ToLower(promptLine(r, prompt, d)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func promptPlatform(r *bufio.Reader) string {
	opts := []string{"all", "hackerone", "bugcrowd", "intigriti", "yeswehack"}
	for {
		fmt.Fprintln(os.Stderr, "Select platform:")
		for i, o := range opts {
			fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, o)
		}
		s := promptLine(r, "Choice [1]: ", "1")
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(opts) {
			return opts[n-1]
		}
		low := strings.ToLower(s)
		for _, o := range opts {
			if o == low {
				return o
			}
		}
		fmt.Fprintf(os.Stderr, "%s\n", col(cYellow, fmt.Sprintf("  pick a number 1-%d (or 'exit')", len(opts))))
	}
}

// promptCategoriesMenu shows the scope categories as a numbered menu and
// returns the chosen set. It re-asks on invalid input, supports "1,3" style
// multi-select, and "0" for all.
func promptCategoriesMenu(r *bufio.Reader, catIDs map[Category][]string) map[Category]bool {
	var available []Category
	for _, c := range allCategories {
		if len(catIDs[c]) > 0 {
			available = append(available, c)
		}
	}
	if len(available) == 0 {
		return map[Category]bool{}
	}
	for {
		fmt.Fprintln(os.Stderr, "\nScope found — what to pull?")
		for i, c := range available {
			fmt.Fprintf(os.Stderr, "  %d) %-10s %d\n", i+1, c, len(catIDs[c]))
		}
		fmt.Fprintln(os.Stderr, "  0) all")
		s := promptLine(r, "Choice (e.g. 1,3 or 0 for all) [0]: ", "0")
		if s == "0" || strings.EqualFold(s, "all") {
			sel := map[Category]bool{}
			for _, c := range available {
				sel[c] = true
			}
			return sel
		}
		picked := map[Category]bool{}
		valid := true
		for _, part := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 1 || n > len(available) {
				valid = false
				break
			}
			picked[available[n-1]] = true
		}
		if valid && len(picked) > 0 {
			return picked
		}
		fmt.Fprintln(os.Stderr, col(cYellow, "  pick numbers from the list (e.g. 1,3) or 0 for all"))
	}
}

func promptRecon(r *bufio.Reader) string {
	for {
		fmt.Fprintln(os.Stderr, "\nRecon depth:")
		fmt.Fprintln(os.Stderr, "  1) scope    — only download & categorize scope")
		fmt.Fprintln(os.Stderr, "  2) passive  — scope + passive subdomain enum + Wayback JS list")
		fmt.Fprintln(os.Stderr, "  3) full     — enum + live probe + crawl + download JS + endpoints")
		switch promptLine(r, "Choice [3]: ", "3") {
		case "1", "scope":
			return "scope"
		case "2", "passive":
			return "passive"
		case "3", "full":
			return "full"
		}
		fmt.Fprintln(os.Stderr, col(cYellow, "  pick 1, 2, or 3 (or 'exit')"))
	}
}
