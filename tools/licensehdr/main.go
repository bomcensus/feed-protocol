// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: Apache-2.0

// Command licensehdr checks or inserts the feed-protocol license header.
//
// Usage:
//
//	go run ./tools/licensehdr [-fix] PATH...
//
// Without -fix it lists files that need the header and exits 1 if there are
// any. With -fix it inserts the header in place.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Rules. Everything that decides which files are handled lives in this block.
// ---------------------------------------------------------------------------

// headerLines is the header every source file carries.
var headerLines = []string{
	"Copyright (C) 2026 JC-Lab",
	"SPDX-License-Identifier: Apache-2.0",
}

// spdxMarker present in the first headScanLines lines means "has header".
const (
	spdxMarker    = "SPDX-License-Identifier: Apache-2.0"
	headScanLines = 10
	genScanLines  = 5
)

// skipDirs are directory names skipped anywhere in the tree.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".nuxt": true, ".output": true,
	"dist": true, "bin": true, ".devstate": true, "testdata": true, "LICENSES": true,
}

// skipPaths are slash-separated directory paths skipped wherever they occur.
var skipPaths = []string{"internal/gen"}

// skipNames are file base names that never get a header.
var skipNames = map[string]bool{
	"go.sum": true, "pnpm-lock.yaml": true, "LICENSE": true,
	".gitignore": true, ".nvmrc": true, "go.mod": true,
}

// skipExts are file extensions that never get a header (docs, data, binary).
var skipExts = map[string]bool{
	".md": true, ".json": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".webp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".lock": true, ".sum": true,
}

// A style says how the header is wrapped in a comment.
type style int

const (
	styleSlash style = iota + 1 // // ...
	styleHash                   // # ...
	styleDash                   // -- ...
	styleHTML                   // <!-- ... -->
	styleCSS                    // /* ... */
	styleHelm                   // {{- /* ... */ -}}
)

// extStyles maps a file extension to its comment style. Files with other
// extensions are ignored, except extensionless files with a shebang (hash).
var extStyles = map[string]style{
	".go": styleSlash, ".ts": styleSlash, ".js": styleSlash, ".mjs": styleSlash,
	".yaml": styleHash, ".yml": styleHash, ".sh": styleHash, ".mk": styleHash,
	".toml": styleHash, ".tpl": styleHash, ".ps1": styleHash,
	".sql": styleDash,
	".vue": styleHTML, ".html": styleHTML,
	".css": styleCSS,
}

// nameStyles maps exact base names (and "Name.*" prefixes) to a style.
var nameStyles = map[string]style{"Makefile": styleHash, "Dockerfile": styleHash}

// ---------------------------------------------------------------------------

func main() {
	fix := flag.Bool("fix", false, "insert missing headers instead of listing them")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: licensehdr [-fix] PATH...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	missing, err := run(flag.Args(), *fix, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "licensehdr:", err)
		os.Exit(2)
	}
	if missing > 0 && !*fix {
		os.Exit(1)
	}
}

// run processes the paths and returns the number of files lacking a header
// (fixed ones included when fix is set).
func run(paths []string, fix bool, out interface{ Write([]byte) (int, error) }) (int, error) {
	n := 0
	handle := func(path string) error {
		changed, err := process(path, fix)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if changed {
			n++
			verb := "missing header:"
			if fix {
				verb = "fixed:"
			}
			fmt.Fprintln(out, verb, path)
		}
		return nil
	}
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return n, err
		}
		if !info.IsDir() {
			if err := handle(root); err != nil {
				return n, err
			}
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && skipDir(p, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			return handle(p)
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func skipDir(path, name string) bool {
	if skipDirs[name] {
		return true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	slash := "/" + filepath.ToSlash(abs)
	for _, s := range skipPaths {
		if strings.HasSuffix(slash, "/"+s) {
			return true
		}
	}
	return false
}

// styleFor returns the comment style for a file, or 0 if it is not handled.
// head is only consulted for extensionless files.
func styleFor(path string, head func() []byte) style {
	base := filepath.Base(path)
	if skipNames[base] {
		return 0
	}
	ext := filepath.Ext(base)
	if skipExts[ext] {
		return 0
	}
	slash := filepath.ToSlash(path)
	if abs, err := filepath.Abs(path); err == nil {
		slash = filepath.ToSlash(abs)
	}
	if isHelmTemplate(slash, ext) {
		return styleHelm
	}
	if s, ok := nameStyles[base]; ok {
		return s
	}
	if i := strings.IndexByte(base, '.'); i > 0 {
		if s, ok := nameStyles[base[:i]]; ok && base[:i] == "Dockerfile" {
			return s
		}
	}
	if s, ok := extStyles[ext]; ok {
		return s
	}
	if ext == "" && bytes.HasPrefix(head(), []byte("#!")) {
		return styleHash
	}
	return 0
}

func isHelmTemplate(slash, ext string) bool {
	if ext != ".yaml" && ext != ".yml" && ext != ".tpl" && ext != ".txt" {
		return false
	}
	i := strings.Index(slash, "deploy/charts/")
	if i < 0 {
		return false
	}
	rest := strings.Split(slash[i+len("deploy/charts/"):], "/")
	return len(rest) >= 3 && rest[1] == "templates"
}

// process checks one file and inserts the header when fix is set. It reports
// whether the file lacked the header.
func process(path string, fix bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	st := styleFor(path, func() []byte { return data })
	if st == 0 {
		return false, nil
	}
	if hasHeader(data) || isGenerated(data) {
		return false, nil
	}
	if !fix {
		return true, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	// WriteFile keeps the mode of an existing file.
	if err := os.WriteFile(path, insertHeader(data, st), info.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}

func firstLines(data []byte, n int) []byte {
	end := 0
	for i := 0; i < n; i++ {
		j := bytes.IndexByte(data[end:], '\n')
		if j < 0 {
			return data
		}
		end += j + 1
	}
	return data[:end]
}

func hasHeader(data []byte) bool {
	return bytes.Contains(firstLines(data, headScanLines), []byte(spdxMarker))
}

func isGenerated(data []byte) bool {
	h := firstLines(data, genScanLines)
	return bytes.Contains(h, []byte("Code generated")) && bytes.Contains(h, []byte("DO NOT EDIT"))
}

// renderHeader returns the comment block (no trailing newline) using nl.
func renderHeader(st style, nl string) string {
	var lines []string
	switch st {
	case styleSlash, styleHash, styleDash:
		prefix := map[style]string{styleSlash: "// ", styleHash: "# ", styleDash: "-- "}[st]
		for _, l := range headerLines {
			lines = append(lines, prefix+l)
		}
	case styleHTML:
		lines = append(lines, "<!--")
		for _, l := range headerLines {
			lines = append(lines, "  "+l)
		}
		lines = append(lines, "-->")
	case styleCSS:
		lines = append(lines, "/*")
		for _, l := range headerLines {
			lines = append(lines, " * "+l)
		}
		lines = append(lines, " */")
	case styleHelm:
		lines = append(lines, "{{- /*")
		for _, l := range headerLines {
			lines = append(lines, "  "+l)
		}
		lines = append(lines, "*/ -}}")
	}
	return strings.Join(lines, nl)
}

// insertHeader puts the header at the top of data, after a UTF-8 BOM, a
// shebang line, or an HTML doctype when present. It keeps the file's line
// ending style.
func insertHeader(data []byte, st style) []byte {
	nl := "\n"
	if i := bytes.IndexByte(data, '\n'); i > 0 && data[i-1] == '\r' {
		nl = "\r\n"
	}
	var prefix []byte
	rest := data
	if bytes.HasPrefix(rest, []byte("\xef\xbb\xbf")) {
		prefix, rest = rest[:3], rest[3:]
	}
	skipFirst := bytes.HasPrefix(rest, []byte("#!"))
	if st == styleHTML && len(rest) >= 9 && strings.EqualFold(string(rest[:9]), "<!doctype") {
		skipFirst = true
	}
	var first []byte
	if skipFirst {
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			first, rest = rest[:i+1], rest[i+1:]
		} else {
			first, rest = append(append([]byte{}, rest...), nl...), nil
		}
	}
	var b bytes.Buffer
	b.Write(prefix)
	b.Write(first)
	b.WriteString(renderHeader(st, nl))
	b.WriteString(nl)
	if len(rest) > 0 {
		b.WriteString(nl)
		b.Write(rest)
	}
	return b.Bytes()
}
