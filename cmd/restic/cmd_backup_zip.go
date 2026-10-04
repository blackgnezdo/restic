package main

import (
	"archive/zip"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/restic/restic/internal/errors"
	"github.com/restic/restic/internal/fs"
	"github.com/restic/restic/internal/global"
	"github.com/restic/restic/internal/ui"
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

// zipPasswordFunc returns the password for an encrypted zip file. retry is
// true if the previous password was wrong.
type zipPasswordFunc func(file string, retry bool) (string, error)

const maxZipPasswordAttempts = 3

// zipPasswords returns the password source selected by the options: a
// password file, or else asking on the terminal.
func zipPasswords(ctx context.Context, opts BackupOptions, term ui.Terminal) zipPasswordFunc {
	return func(file string, retry bool) (string, error) {
		if opts.ZipPasswordFile != "" {
			if retry {
				return "", errors.Fatalf("the password in %v does not match %v", opts.ZipPasswordFile, file)
			}
			return global.LoadPasswordFromFile(opts.ZipPasswordFile)
		}
		pw, err := term.ReadPassword(ctx, fmt.Sprintf("enter password for %v: ", filepath.Base(file)))
		if err != nil {
			return "", fmt.Errorf("unable to read zip password: %w", err)
		}
		return pw, nil
	}
}

// openZipFS opens all zip files and returns a file system exposing their
// contents. The zip files are read in place, nothing is extracted. The
// password of encrypted archives is checked up front, so that a wrong
// password is reported before any data is uploaded.
func openZipFS(files []string, password zipPasswordFunc) (fs.FS, func(), error) {
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

		pw, err := zipPassword(name, &zr.Reader, password)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		mounts = append(mounts, fs.ZipMount{Name: zipMountName(name), Reader: &zr.Reader, Password: pw})
	}

	filesys, err := fs.NewZip(mounts)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("unable to mount zip files: %w", err)
	}
	return filesys, closeAll, nil
}

// zipPassword returns the password for the archive, or "" if it is not encrypted.
func zipPassword(name string, zr *zip.Reader, password zipPasswordFunc) (string, error) {
	kind, entry := fs.ZipEncryptionOf(zr)
	switch kind {
	case fs.ZipNotEncrypted:
		return "", nil
	case fs.ZipUnsupportedEncryption:
		return "", errors.Fatalf("%v: entry %q uses AES or strong zip encryption, which is not supported (only traditional zip encryption)", name, entry.Name)
	}

	retry := false
	for attempt := 0; attempt < maxZipPasswordAttempts; attempt++ {
		pw, err := password(name, retry)
		if err != nil {
			return "", err
		}
		if pw == "" {
			return "", errors.Fatalf("%v is encrypted but no password was given, use --zip-password-file or run restic on a terminal", name)
		}
		err = fs.CheckZipPassword(zr, pw)
		if err == nil {
			return pw, nil
		}
		if !errors.Is(err, fs.ErrZipPassword) {
			return "", err
		}
		retry = true
	}
	return "", errors.Fatalf("%v: wrong password", name)
}
