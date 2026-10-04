package fs

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"hash/crc32"
	"io"
	"testing"

	rtest "github.com/restic/restic/internal/test"
)

// zipCryptoEncrypt is the encrypting counterpart of zipCryptoReader. It is
// written independently so that the tests do not only prove that decryption
// inverts our own encryption; the real format is covered by the integration
// check against Info-ZIP archives.
func zipCryptoEncrypt(password string, plain []byte) []byte {
	k := [3]uint32{0x12345678, 0x23456789, 0x34567890}
	update := func(b byte) {
		k[0] = crc32.IEEETable[byte(k[0])^b] ^ (k[0] >> 8)
		k[1] = (k[1]+uint32(byte(k[0])))*134775813 + 1
		k[2] = crc32.IEEETable[byte(k[2])^byte(k[1]>>24)] ^ (k[2] >> 8)
	}
	for _, c := range []byte(password) {
		update(c)
	}
	out := make([]byte, len(plain))
	for i, p := range plain {
		t := uint16(k[2]) | 2
		out[i] = p ^ byte((t*(t^1))>>8)
		update(p)
	}
	return out
}

func buildEncryptedZip(t testing.TB, password string, entries map[string][]byte, method uint16) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		var body []byte
		switch method {
		case zip.Store:
			body = content
		case zip.Deflate:
			var c bytes.Buffer
			fw, err := flate.NewWriter(&c, flate.DefaultCompression)
			rtest.OK(t, err)
			_, err = fw.Write(content)
			rtest.OK(t, err)
			rtest.OK(t, fw.Close())
			body = c.Bytes()
		}
		crc := crc32.ChecksumIEEE(content)
		plain := append(bytes.Repeat([]byte{0xA5}, 11), byte(crc>>24))
		enc := zipCryptoEncrypt(password, append(plain, body...))

		w, err := zw.CreateRaw(&zip.FileHeader{
			Name:               name,
			Method:             method,
			Flags:              zipFlagEncrypted,
			CRC32:              crc,
			CompressedSize64:   uint64(len(enc)),
			UncompressedSize64: uint64(len(content)),
		})
		rtest.OK(t, err)
		_, err = w.Write(enc)
		rtest.OK(t, err)
	}
	rtest.OK(t, zw.Close())
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	rtest.OK(t, err)
	return zr
}

func TestZipCrypto(t *testing.T) {
	entries := map[string][]byte{
		"a/big.txt": bytes.Repeat([]byte("hello zipcrypto\n"), 20000),
		"small":     []byte("x"),
		"empty":     {},
	}

	for name, method := range map[string]uint16{"deflate": zip.Deflate, "store": zip.Store} {
		t.Run(name, func(t *testing.T) {
			zr := buildEncryptedZip(t, "pässword", entries, method)

			kind, _ := ZipEncryptionOf(zr)
			rtest.Equals(t, ZipCrypto, kind)
			rtest.OK(t, CheckZipPassword(zr, "pässword"))

			err := CheckZipPassword(zr, "wrong")
			rtest.Assert(t, errors.Is(err, ErrZipPassword), "wrong password: got %v", err)

			z, err := NewZip([]ZipMount{{Name: "m", Reader: zr, Password: "pässword"}})
			rtest.OK(t, err)
			for fname, want := range entries {
				f, err := z.OpenFile("/m/"+fname, 0, false)
				rtest.OK(t, err)
				got, err := io.ReadAll(f)
				rtest.OK(t, err)
				rtest.OK(t, f.Close())
				rtest.Assert(t, bytes.Equal(want, got), "%v: content differs", fname)
			}

			// reading with the wrong or without password must fail, never return garbage
			for _, pw := range []string{"wrong", ""} {
				z, err := NewZip([]ZipMount{{Name: "m", Reader: zr, Password: pw}})
				rtest.OK(t, err)
				f, err := z.OpenFile("/m/a/big.txt", 0, true)
				rtest.OK(t, err)
				err = f.MakeReadable()
				if err == nil {
					_, err = io.ReadAll(f)
				}
				rtest.Assert(t, errors.Is(err, ErrZipPassword), "password %q: got %v", pw, err)
				_ = f.Close()
			}
		})
	}
}

func TestZipUnsupportedEncryption(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: "aes", Method: zipMethodAES, Flags: zipFlagEncrypted, CompressedSize64: 4, UncompressedSize64: 4})
	rtest.OK(t, err)
	_, err = w.Write([]byte("1234"))
	rtest.OK(t, err)
	rtest.OK(t, zw.Close())
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	rtest.OK(t, err)

	kind, entry := ZipEncryptionOf(zr)
	rtest.Equals(t, ZipUnsupportedEncryption, kind)
	rtest.Equals(t, "aes", entry.Name)

	z, err := NewZip([]ZipMount{{Name: "m", Reader: zr, Password: "x"}})
	rtest.OK(t, err)
	f, err := z.OpenFile("/m/aes", 0, true)
	rtest.OK(t, err)
	rtest.Assert(t, f.MakeReadable() != nil, "opened AES entry")
}
