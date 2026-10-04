package fs

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/restic/restic/internal/data"
	rtest "github.com/restic/restic/internal/test"
)

func buildZip(t testing.TB, entries map[string]string, links map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mtime := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	for name, content := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mtime})
		rtest.OK(t, err)
		_, err = w.Write([]byte(content))
		rtest.OK(t, err)
	}
	for name, target := range links {
		fh := &zip.FileHeader{Name: name, Modified: mtime}
		fh.SetMode(os.ModeSymlink | 0777)
		w, err := zw.CreateHeader(fh)
		rtest.OK(t, err)
		_, err = w.Write([]byte(target))
		rtest.OK(t, err)
	}
	rtest.OK(t, zw.Close())
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	rtest.OK(t, err)
	return zr
}

func TestZipFS(t *testing.T) {
	zr := buildZip(t, map[string]string{
		"Takeout/a/b.txt": "bee",
		"Takeout/c.txt":   "",
		"../escape.txt":   "x",
		"Takeout/dup.txt": "old",
	}, map[string]string{"Takeout/link": "c.txt"})
	// duplicate entry, last one wins
	zr2 := buildZip(t, map[string]string{"Takeout/dup.txt": "newer"}, nil)
	zr.File = append(zr.File, zr2.File...)

	z, err := NewZip([]ZipMount{{Name: "t1", Reader: zr}})
	rtest.OK(t, err)

	// implicit directories are synthesized, children are sorted
	names, err := Readdirnames(z, "/", 0)
	rtest.OK(t, err)
	rtest.Equals(t, []string{"t1"}, names)
	names, err = Readdirnames(z, "/t1/Takeout", 0)
	rtest.OK(t, err)
	rtest.Equals(t, []string{"a", "c.txt", "dup.txt", "link"}, names)

	// entries must not escape the mount
	_, err = z.Lstat("/escape.txt")
	rtest.Assert(t, err != nil, "escaping entry visible")
	_, err = z.Lstat("/t1/escape.txt")
	rtest.Assert(t, err != nil, "escaping entry visible in mount")

	fi, err := z.Lstat("/t1/Takeout/a/b.txt")
	rtest.OK(t, err)
	rtest.Equals(t, int64(3), fi.Size)
	rtest.Equals(t, time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix(), fi.ModTime.Unix())
	rtest.Assert(t, fi.Mode.IsRegular(), "not regular")

	// metadata-only files cannot be read until MakeReadable
	f, err := z.OpenFile("/t1/Takeout/a/b.txt", O_NOFOLLOW, true)
	rtest.OK(t, err)
	_, err = f.Read(make([]byte, 1))
	rtest.Assert(t, err != nil, "read before MakeReadable succeeded")
	rtest.OK(t, f.MakeReadable())
	buf, err := io.ReadAll(f)
	rtest.OK(t, err)
	rtest.Equals(t, "bee", string(buf))
	rtest.OK(t, f.Close())

	f, err = z.OpenFile("/t1/Takeout/dup.txt", 0, false)
	rtest.OK(t, err)
	buf, _ = io.ReadAll(f)
	rtest.Equals(t, "newer", string(buf))
	rtest.OK(t, f.Close())

	// an empty file is legitimate
	f, err = z.OpenFile("/t1/Takeout/c.txt", 0, false)
	rtest.OK(t, err)
	buf, err = io.ReadAll(f)
	rtest.OK(t, err)
	rtest.Equals(t, 0, len(buf))
	rtest.OK(t, f.Close())

	// symlinks carry their target
	f, err = z.OpenFile("/t1/Takeout/link", O_NOFOLLOW, true)
	rtest.OK(t, err)
	node, err := f.ToNode(false, t.Logf)
	rtest.OK(t, err)
	rtest.Equals(t, data.NodeTypeSymlink, node.Type)
	rtest.Equals(t, "c.txt", node.LinkTarget)
	rtest.OK(t, f.Close())

	_, err = z.OpenFile("/t1/Takeout/c.txt", O_DIRECTORY, true)
	rtest.Assert(t, err != nil, "opened a file as directory")
	_, err = z.OpenFile("/nope", 0, true)
	rtest.Assert(t, err != nil, "opened missing file")
}

func TestZipFSMounts(t *testing.T) {
	zr := buildZip(t, map[string]string{"x": "1"}, nil)
	_, err := NewZip([]ZipMount{{Name: "a", Reader: zr}, {Name: "a", Reader: zr}})
	rtest.Assert(t, err != nil, "duplicate mount accepted")
	_, err = NewZip([]ZipMount{{Name: "a/b", Reader: zr}})
	rtest.Assert(t, err != nil, "invalid mount name accepted")

	z, err := NewZip([]ZipMount{{Name: "a", Reader: zr}, {Name: "b", Reader: zr}})
	rtest.OK(t, err)
	names, err := Readdirnames(z, "/", 0)
	rtest.OK(t, err)
	rtest.Equals(t, []string{"a", "b"}, names)
}

func TestZipFSConcurrentReads(t *testing.T) {
	entries := map[string]string{}
	for i := 0; i < 20; i++ {
		entries[string(rune('a'+i))] = string(bytes.Repeat([]byte{byte('a' + i)}, 100000))
	}
	z, err := NewZip([]ZipMount{{Name: "m", Reader: buildZip(t, entries, nil)}})
	rtest.OK(t, err)

	var wg sync.WaitGroup
	for name, want := range entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := z.OpenFile("/m/"+name, 0, true)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = f.Close() }()
			if err := f.MakeReadable(); err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(f)
			if err != nil || string(got) != want {
				t.Errorf("%v: content mismatch (err %v)", name, err)
			}
		}()
	}
	wg.Wait()
}
