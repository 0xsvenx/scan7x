package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// useColor is set once at startup and gates all ANSI output.
var useColor bool

// ANSI escape codes (bright variants for a crisp look on dark terminals).
const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[91m"
	cGreen   = "\033[92m"
	cYellow  = "\033[93m"
	cBlue    = "\033[94m"
	cMagenta = "\033[95m"
	cCyan    = "\033[96m"
	cWhite   = "\033[97m"
	cGray    = "\033[90m"
)

// col wraps s in an ANSI code when color is enabled.
func col(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + cReset
}

// setupColor decides whether to emit ANSI codes and enables virtual-terminal
// processing on Windows. Honors -no-color and the NO_COLOR convention, and
// stays quiet when stdout is not a terminal (e.g. piped to a file).
func setupColor(disable bool) {
	if disable || os.Getenv("NO_COLOR") != "" {
		useColor = false
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		useColor = false
		return
	}
	enableVT()
	useColor = true
}

var bannerArt = []string{
	`███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗  ██╗`,
	`██╔════╝██╔════╝██╔══██╗████╗  ██║╚════██║╚██╗██╔╝`,
	`███████╗██║     ███████║██╔██╗ ██║    ██╔╝ ╚███╔╝ `,
	`╚════██║██║     ██╔══██║██║╚██╗██║   ██╔╝  ██╔██╗ `,
	`███████║╚██████╗██║  ██║██║ ╚████║   ██║  ██╔╝ ██╗`,
	`╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝  ╚═╝  ╚═╝`,
}

// bannerShades is a cyan→blue vertical gradient (256-color) for the logo rows.
var bannerShades = []string{
	"\033[38;5;51m", "\033[38;5;45m", "\033[38;5;39m",
	"\033[38;5;33m", "\033[38;5;27m", "\033[38;5;21m",
}

// printBanner renders the scan7x logo and tagline to stderr. On a real
// terminal it reveals the logo row by row with a color gradient; when output
// is piped (or color is off) it prints instantly so scripts stay fast.
func printBanner() {
	animate := useColor
	fmt.Fprintln(os.Stderr)
	for i, line := range bannerArt {
		code := cCyan
		if animate && i < len(bannerShades) {
			code = bannerShades[i]
		}
		fmt.Fprintln(os.Stderr, "  "+col(code, line))
		if animate {
			time.Sleep(55 * time.Millisecond)
		}
	}
	if animate {
		time.Sleep(90 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+col(cBold+cWhite, "scan7x")+" "+
		col(cGray, "· bug-bounty recon & enumeration engine")+"  "+col(cGreen, "v"+version))
	fmt.Fprintln(os.Stderr, "  "+col(cDim, "pick a program on any platform  →  scan  →  organized recon folder"))
	fmt.Fprintln(os.Stderr)
}

// colorizeTags adds color to the [*] / [+] / [warn] / [!] log prefixes.
func colorizeTags(s string) string {
	replacements := []struct {
		tag, code string
	}{
		{"[+]", cGreen},
		{"[*]", cCyan},
		{"[warn]", cYellow},
		{"[!]", cRed},
	}
	for _, r := range replacements {
		if strings.Contains(s, r.tag) {
			s = strings.Replace(s, r.tag, col(r.code, r.tag), 1)
		}
	}
	return s
}
