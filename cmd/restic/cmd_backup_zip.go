package main

import (
	"archive/zip"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/restic/restic/internal/errors"
	"github.com/restic/restic/internal/fs"
)

// zipMountName returns the name below which the contents of the zip file are
// stored in the snapshot.
func zipMountName(file string) string {
	base := filepath.Base(file)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// zipTargets returns the snapshot paths for the given zip files.
func zipTargets(files []string) []string {
	targets := make([]string, 0, len(files))
	for _, f := range files {
		targets = append(targets, "/"+zipMountName(f))
	}
	return targets
}

// openZipFS opens all zip files and returns a file system exposing their
// contents. The zip files are read in place, nothing is extracted.
func openZipFS(files []string) (fs.FS, func(), error) {
	var closers []func() error
	closeAll := func() {
		for _, c := range closers {
			_ = c()
		}
	}

	mounts := make([]fs.ZipMount, 0, len(files))
	for _, name := range files {
		zr, err := zip.OpenReader(name)
		if err != nil {
			closeAll()
			return nil, nil, errors.Fatalf("unable to open zip file %v: %v", name, err)
		}
		closers = append(closers, zr.Close)
		mounts = append(mounts, fs.ZipMount{Name: zipMountName(name), Reader: &zr.Reader})
	}

	filesys, err := fs.NewZip(mounts)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("unable to mount zip files: %w", err)
	}
	return filesys, closeAll, nil
}
