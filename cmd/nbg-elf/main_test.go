package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"nbg-elf/internal/elfstr"
)

func TestResolveManifestOutputPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	outputPath := filepath.Join(dir, "out.vmp")
	if err := os.WriteFile(outputPath, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write output: %v", err)
	}
	if got := resolveManifestOutputPath(manifestPath, "out.vmp"); got != outputPath {
		t.Fatalf("relative output resolved to %q want %q", got, outputPath)
	}
	abs := filepath.Join(dir, "abs.vmp")
	if got := resolveManifestOutputPath(manifestPath, abs); got != abs {
		t.Fatalf("absolute output resolved to %q want %q", got, abs)
	}
	if got := resolveManifestOutputPath(manifestPath, "missing.vmp"); got != "missing.vmp" {
		t.Fatalf("missing output resolved to %q want original", got)
	}
}

func TestResolveManifestInputPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	inputPath := filepath.Join(dir, "input.elf")
	if err := os.WriteFile(inputPath, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if got := resolveManifestInputPath(manifestPath, "input.elf"); got != inputPath {
		t.Fatalf("relative input resolved to %q want %q", got, inputPath)
	}
	abs := filepath.Join(dir, "abs.elf")
	if got := resolveManifestInputPath(manifestPath, abs); got != abs {
		t.Fatalf("absolute input resolved to %q want %q", got, abs)
	}
	if got := resolveManifestInputPath(manifestPath, "missing.elf"); got != "missing.elf" {
		t.Fatalf("missing input resolved to %q want original", got)
	}
}

func TestFlagWasSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Bool("lazy-callsite", false, "")
	if err := fs.Parse([]string{"-lazy-callsite"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !flagWasSet(fs, "lazy-callsite") {
		t.Fatalf("expected lazy-callsite to be marked set")
	}
	if flagWasSet(fs, "preset") {
		t.Fatalf("unexpected preset flag")
	}
}

func TestApplyEncryptFlagOverridesOnlyVisitsExplicitFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	limit := fs.Int("lazy-callsite-limit", 0, "")
	keepSections := fs.Bool("keep-sections", false, "")
	if err := fs.Parse([]string{"-lazy-callsite-limit", "5"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	opts := elfstr.Options{KeepSections: true}
	applyEncryptFlagOverrides(fs, &opts, map[string]func(){
		"lazy-callsite-limit": func() { opts.LazyCallsiteLimit = *limit },
		"keep-sections":       func() { opts.KeepSections = *keepSections },
	})
	if opts.LazyCallsiteLimit != 5 {
		t.Fatalf("lazy limit got %d want 5", opts.LazyCallsiteLimit)
	}
	if !opts.KeepSections {
		t.Fatalf("keep-sections should not be overridden by an implicit default")
	}
}
