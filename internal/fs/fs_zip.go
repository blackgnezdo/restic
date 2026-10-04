package fs

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/restic/restic/internal/data"
)

// ZipMount describes a zip archive that is exposed as the directory Name
// (a single path element) of a ZipFS.
type ZipMount struct {
	Name   string
	Reader *zip.Reader
}

type zipItem struct {
	fi       *ExtendedFileInfo
	file     *zip.File // nil for directories
	children []string
}

type zipFS struct {
	items map[string]*zipItem
}

// statically ensure that zipFS implements FS.
var _ FS = &zipFS{}

// NewZip returns a read-only FS which exposes the contents of the given zip
// archives without extracting them. Each archive is mounted as a top-level
// directory "/<Name>". Several archives can be read concurrently, as every
// opened entry uses its own reader.
func NewZip(mounts []ZipMount) (FS, error) {
	z := &zipFS{items: make(map[string]*zipItem)}
	z.items["/"] = &zipItem{fi: dirInfo("/", time.Time{})}

	for _, m := range mounts {
		if m.Name == "" || strings.Contains(m.Name, "/") {
			return nil, fmt.Errorf("invalid zip mount name %q", m.Name)
		}
		root := "/" + m.Name
		if _, ok := z.items[root]; ok {
			return nil, fmt.Errorf("duplicate zip mount name %q", m.Name)
		}
		z.addDir(root, time.Time{})

		for _, f := range m.Reader.File {
			name := path.Clean("/" + m.Name + "/" + f.Name)
			if !strings.HasPrefix(name, root+"/") {
				// entries such as "../x" must not escape the mount
				continue
			}

			fi := zipFileInfo(f)
			if fi.Mode.IsDir() {
				z.addDir(name, fi.ModTime)
				z.items[name].fi = fi
				continue
			}

			z.addDir(path.Dir(name), fi.ModTime)
			if old, ok := z.items[name]; ok && old.file != nil {
				// duplicate entry, the last one wins like in most unzip tools
				old.file, old.fi = f, fi
				continue
			}
			z.items[name] = &zipItem{fi: fi, file: f}
			z.link(name)
		}
	}

	for _, it := range z.items {
		sort.Strings(it.children)
	}
	return z, nil
}

// addDir makes sure that dir and all its parents exist.
func (z *zipFS) addDir(dir string, mtime time.Time) {
	for {
		if _, ok := z.items[dir]; ok {
			return
		}
		z.items[dir] = &zipItem{fi: dirInfo(dir, mtime)}
		z.link(dir)
		dir = path.Dir(dir)
	}
}

func (z *zipFS) link(name string) {
	parent := z.items[path.Dir(name)]
	if parent == nil {
		z.addDir(path.Dir(name), z.items[name].fi.ModTime)
		parent = z.items[path.Dir(name)]
	}
	parent.children = append(parent.children, path.Base(name))
}

func dirInfo(name string, mtime time.Time) *ExtendedFileInfo {
	return &ExtendedFileInfo{
		Name:    path.Base(name),
		Mode:    os.ModeDir | 0755,
		ModTime: mtime,
	}
}

func zipFileInfo(f *zip.File) *ExtendedFileInfo {
	mode := f.Mode()
	if mode.IsDir() {
		mode |= 0755
	} else if mode.Perm() == 0 {
		mode |= 0644
	}
	fi := &ExtendedFileInfo{
		Name:    path.Base(path.Clean("/" + f.Name)),
		Mode:    mode,
		ModTime: f.Modified,
		Size:    int64(f.UncompressedSize64),
	}
	if !mode.IsRegular() {
		fi.Size = 0
	}
	return fi
}

func (z *zipFS) lookup(name string) (string, *zipItem, bool) {
	name = readerCleanPath(name)
	it, ok := z.items[name]
	return name, it, ok
}

func (z *zipFS) OpenFile(name string, flag int, metadataOnly bool) (File, error) {
	if flag & ^(O_RDONLY|O_NOFOLLOW|O_DIRECTORY) != 0 {
		return nil, pathError("open", name,
			fmt.Errorf("invalid combination of flags 0x%x", flag))
	}

	name, it, ok := z.lookup(name)
	if !ok {
		return nil, pathError("open", name, syscall.ENOENT)
	}

	if it.fi.Mode.IsDir() {
		return fakeDir{
			fakeFile: fakeFile{name: it.fi.Name, fi: it.fi},
			entries:  slices.Clone(it.children),
		}, nil
	}
	if flag&O_DIRECTORY != 0 {
		return nil, pathError("open", name, syscall.ENOTDIR)
	}

	f := &zipFile{
		fakeFile: fakeFile{name: it.fi.Name, fi: it.fi},
		item:     it,
	}
	if !metadataOnly {
		if err := f.MakeReadable(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (z *zipFS) Lstat(name string) (*ExtendedFileInfo, error) {
	name, it, ok := z.lookup(name)
	if !ok {
		return nil, pathError("lstat", name, os.ErrNotExist)
	}
	return it.fi, nil
}

func (z *zipFS) Join(elem ...string) string   { return path.Join(elem...) }
func (z *zipFS) Separator() string            { return "/" }
func (z *zipFS) Abs(p string) (string, error) { return readerCleanPath(p), nil }
func (z *zipFS) Clean(p string) string        { return path.Clean(p) }
func (z *zipFS) VolumeName(_ string) string   { return "" }
func (z *zipFS) IsAbs(_ string) bool          { return true }
func (z *zipFS) Dir(p string) string          { return path.Dir(p) }
func (z *zipFS) Base(p string) string         { return path.Base(p) }

// zipFile is a file inside a zip archive. The entry is only opened (and thus
// decompression only starts) in MakeReadable.
type zipFile struct {
	fakeFile
	item *zipItem
	rc   io.ReadCloser
}

var _ File = &zipFile{}

func (f *zipFile) MakeReadable() error {
	if f.rc != nil {
		return nil
	}
	rc, err := f.item.file.Open()
	if err != nil {
		return pathError("open", f.name, err)
	}
	f.rc = rc
	return nil
}

func (f *zipFile) Read(p []byte) (int, error) {
	if f.rc == nil {
		return 0, pathError("read", f.name, os.ErrInvalid)
	}
	return f.rc.Read(p)
}

func (f *zipFile) Close() error {
	if f.rc == nil {
		return nil
	}
	err := f.rc.Close()
	f.rc = nil
	return err
}

func (f *zipFile) ToNode(ignoreXattrListError bool, warnf func(format string, args ...any)) (*data.Node, error) {
	node, err := f.fakeFile.ToNode(ignoreXattrListError, warnf)
	if err != nil {
		return nil, err
	}
	if node.Type == data.NodeTypeSymlink {
		// the link target is stored as the content of the entry
		rc, err := f.item.file.Open()
		if err != nil {
			return node, err
		}
		defer func() { _ = rc.Close() }()
		target, err := io.ReadAll(io.LimitReader(rc, 64*1024))
		if err != nil {
			return node, err
		}
		node.LinkTarget = string(target)
	}
	return node, nil
}
