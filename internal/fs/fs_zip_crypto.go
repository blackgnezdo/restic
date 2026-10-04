package fs

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

// ZipEncryption describes how the entries of a zip archive are encrypted.
type ZipEncryption int

const (
	// ZipNotEncrypted means that no entry is encrypted.
	ZipNotEncrypted ZipEncryption = iota
	// ZipCrypto is the traditional PKWARE encryption, which is supported.
	ZipCrypto
	// ZipUnsupportedEncryption covers AES (WinZip) and the PKWARE strong
	// encryption, which are not supported.
	ZipUnsupportedEncryption
)

const (
	zipFlagEncrypted      = 0x1
	zipFlagDataDescriptor = 0x8
	zipFlagStrongCrypto   = 0x40
	zipMethodAES          = 99
)

// ErrZipPassword is returned when an encrypted entry could not be decrypted
// with the given password.
var ErrZipPassword = errors.New("wrong password or corrupt data")

func zipEntryEncryption(f *zip.File) ZipEncryption {
	switch {
	case f.Flags&zipFlagEncrypted == 0:
		return ZipNotEncrypted
	case f.Flags&zipFlagStrongCrypto != 0 || f.Method == zipMethodAES:
		return ZipUnsupportedEncryption
	default:
		return ZipCrypto
	}
}

// ZipEncryptionOf returns the strongest kind of encryption used by any entry
// of the archive, together with the entry that uses it.
func ZipEncryptionOf(r *zip.Reader) (ZipEncryption, *zip.File) {
	kind, first := ZipNotEncrypted, (*zip.File)(nil)
	for _, f := range r.File {
		if k := zipEntryEncryption(f); k > kind {
			kind, first = k, f
		}
	}
	return kind, first
}

// CheckZipPassword verifies password by fully decrypting the smallest
// encrypted entry of the archive and checking its CRC.
func CheckZipPassword(r *zip.Reader, password string) error {
	var smallest *zip.File
	for _, f := range r.File {
		if zipEntryEncryption(f) == ZipCrypto &&
			(smallest == nil || f.CompressedSize64 < smallest.CompressedSize64) {
			smallest = f
		}
	}
	if smallest == nil {
		return nil
	}
	rc, err := openZipEntry(smallest, password)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	_, err = io.Copy(io.Discard, rc)
	return err
}

// openZipEntry opens an entry, decrypting it if necessary.
func openZipEntry(f *zip.File, password string) (io.ReadCloser, error) {
	switch zipEntryEncryption(f) {
	case ZipNotEncrypted:
		return f.Open()
	case ZipUnsupportedEncryption:
		return nil, fmt.Errorf("%v: AES or strong zip encryption is not supported, only traditional zip encryption", f.Name)
	}
	if password == "" {
		return nil, fmt.Errorf("%v: %w (no password given)", f.Name, ErrZipPassword)
	}

	raw, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}

	var header [12]byte
	if _, err := io.ReadFull(raw, header[:]); err != nil {
		return nil, fmt.Errorf("%v: reading encryption header: %w", f.Name, err)
	}
	dec := newZipCryptoReader(raw, password)
	dec.decrypt(header[:])

	// The check byte is the high byte of the CRC, or of the modification
	// time if the CRC was not yet known when the entry was written. A
	// mismatch is a reliable "wrong password", a match is only 1 in 256.
	check := header[11]
	if check != byte(f.CRC32>>24) &&
		(f.Flags&zipFlagDataDescriptor == 0 || check != byte(f.ModifiedTime>>8)) { //nolint:staticcheck // the DOS time is what the check byte is derived from
		return nil, fmt.Errorf("%v: %w", f.Name, ErrZipPassword)
	}

	var body io.Reader = dec
	var closer io.Closer = io.NopCloser(nil)
	switch f.Method {
	case zip.Store:
	case zip.Deflate:
		fr := flate.NewReader(dec)
		body, closer = fr, fr
	default:
		return nil, fmt.Errorf("%v: unsupported compression method %d for encrypted entry", f.Name, f.Method)
	}

	return &zipVerifyReader{
		r:      body,
		closer: closer,
		hash:   crc32.NewIEEE(),
		name:   f.Name,
		crc:    f.CRC32,
		size:   f.UncompressedSize64,
	}, nil
}

// zipVerifyReader checks size and CRC at the end of the stream. For
// encrypted entries this is what reliably detects a wrong password.
type zipVerifyReader struct {
	r      io.Reader
	closer io.Closer
	hash   hash.Hash32
	name   string
	crc    uint32
	size   uint64
	n      uint64
}

func (v *zipVerifyReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	_, _ = v.hash.Write(p[:n])
	v.n += uint64(n)
	if errors.Is(err, io.EOF) {
		if v.n != v.size || (v.crc != 0 && v.hash.Sum32() != v.crc) {
			return n, fmt.Errorf("%v: %w", v.name, ErrZipPassword)
		}
	} else if err != nil {
		// garbage after decrypting with a wrong password usually fails
		// while inflating
		err = fmt.Errorf("%v: %w (%v)", v.name, ErrZipPassword, err)
	}
	return n, err
}

func (v *zipVerifyReader) Close() error { return v.closer.Close() }

// zipCryptoReader implements the traditional PKWARE stream cipher.
type zipCryptoReader struct {
	r          io.Reader
	k0, k1, k2 uint32
}

func newZipCryptoReader(r io.Reader, password string) *zipCryptoReader {
	z := &zipCryptoReader{r: r, k0: 0x12345678, k1: 0x23456789, k2: 0x34567890}
	for i := 0; i < len(password); i++ {
		z.update(password[i])
	}
	return z
}

func zipCRC32Update(crc uint32, b byte) uint32 {
	return crc32.IEEETable[byte(crc)^b] ^ (crc >> 8)
}

func (z *zipCryptoReader) update(b byte) {
	z.k0 = zipCRC32Update(z.k0, b)
	z.k1 = (z.k1+uint32(byte(z.k0)))*134775813 + 1
	z.k2 = zipCRC32Update(z.k2, byte(z.k1>>24))
}

// decrypt decrypts buf in place.
func (z *zipCryptoReader) decrypt(buf []byte) {
	for i, c := range buf {
		t := uint16(z.k2) | 2
		p := c ^ byte((t*(t^1))>>8)
		z.update(p)
		buf[i] = p
	}
}

func (z *zipCryptoReader) Read(p []byte) (int, error) {
	n, err := z.r.Read(p)
	z.decrypt(p[:n])
	return n, err
}
