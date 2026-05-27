package main

import (
	"os"
	"path/filepath"
	"testing"
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
