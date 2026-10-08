package osv

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Signatures of the zip format (APPNOTE 4.3).
const (
	sigLocalFile      = 0x04034b50
	sigDataDescriptor = 0x08074b50
	sigCentralDir     = 0x02014b50
	sigEndOfCentral   = 0x06054b50
	zip64ExtraID      = 0x0001
	flagEncrypted     = 0x1
	flagDescriptor    = 0x8
	methodStore       = 0
	methodDeflate     = 8
)

// readZip calls fn with the name and content of every file of the zip in r, in the order of the archive, reading
// only forward: archive/zip needs random access and would need the whole download on disk. It stops at the central
// directory, which repeats the local headers.
func readZip(r io.Reader, maxSize int64, fn func(name string, body []byte) error) error {
	// flate reads exactly up to the end of its stream from an io.ByteReader, so the data descriptor that may follow
	// it stays in br.
	br := bufio.NewReaderSize(r, 1<<16)
	for {
		var sig uint32
		if err := binary.Read(br, binary.LittleEndian, &sig); err != nil {
			return fmt.Errorf("zip: %w", unexpected(err))
		}
		switch sig {
		case sigLocalFile:
		case sigCentralDir, sigEndOfCentral:
			return readTrailer(br, sig)
		default:
			return fmt.Errorf("zip: unexpected signature %#x", sig)
		}
		name, body, err := readEntry(br, maxSize)
		if err != nil {
			return fmt.Errorf("zip entry %q: %w", name, err)
		}
		if err := fn(name, body); err != nil {
			return err
		}
	}
}

// readTrailer reads the central directory to its end record, so that a download cut short after the last entry is
// an error too.
func readTrailer(br *bufio.Reader, sig uint32) error {
	rest, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}
	end := []byte{0x50, 0x4b, 0x05, 0x06}
	if sig == sigEndOfCentral {
		rest = append(end, rest...)
	}
	// The end record has 22 bytes plus a comment of at most 65535.
	if i := bytes.LastIndex(rest, end); i < 0 || len(rest)-i < 22 {
		return fmt.Errorf("zip: %w", io.ErrUnexpectedEOF)
	}
	return nil
}

// localHeader is the fixed part of a local file header after its signature.
type localHeader struct {
	Version, Flags, Method, Time, Date uint16
	CRC32, CompressedSize, Size        uint32
	NameLen, ExtraLen                  uint16
}

func readEntry(br *bufio.Reader, maxSize int64) (string, []byte, error) {
	var h localHeader
	if err := binary.Read(br, binary.LittleEndian, &h); err != nil {
		return "", nil, unexpected(err)
	}
	nameExtra := make([]byte, int(h.NameLen)+int(h.ExtraLen))
	if _, err := io.ReadFull(br, nameExtra); err != nil {
		return "", nil, unexpected(err)
	}
	name := string(nameExtra[:h.NameLen])
	if h.Flags&flagEncrypted != 0 {
		return name, nil, errors.New("encrypted")
	}
	compressed, size := uint64(h.CompressedSize), uint64(h.Size)
	if h.CompressedSize == 0xffffffff || h.Size == 0xffffffff {
		var ok bool
		if size, compressed, ok = zip64Sizes(nameExtra[h.NameLen:]); !ok {
			return name, nil, errors.New("zip64 sizes missing")
		}
	}
	descriptor := h.Flags&flagDescriptor != 0
	if compressed > 1<<40 || size > 1<<40 {
		return name, nil, errors.New("entry too large")
	}

	entry := &io.LimitedReader{R: br, N: int64(compressed)} //nolint:gosec // bounded above
	var data io.Reader
	switch {
	case h.Method == methodDeflate && descriptor:
		data = flate.NewReader(br)
	case h.Method == methodDeflate:
		data = flate.NewReader(entry)
	case h.Method == methodStore && !descriptor:
		data = entry
	default:
		return name, nil, fmt.Errorf("unsupported method %d (flags %#x)", h.Method, h.Flags)
	}
	sum := crc32.NewIEEE()
	var buf bytes.Buffer
	n, err := io.Copy(io.MultiWriter(&buf, sum), io.LimitReader(data, maxSize+1))
	if err != nil {
		return name, nil, unexpected(err)
	}
	if n > maxSize {
		return name, nil, fmt.Errorf("larger than %d bytes", maxSize)
	}
	if !descriptor {
		// A deflate stream may end before its compressed size; skip the rest of the entry.
		if _, err := io.Copy(io.Discard, entry); err != nil {
			return name, nil, unexpected(err)
		}
	} else {
		crc, err := readDescriptor(br, h.Version >= 45)
		if err != nil {
			return name, nil, err
		}
		h.CRC32, size = crc, uint64(n) //nolint:gosec // io.Copy counts are never negative
	}
	if uint64(n) != size || sum.Sum32() != h.CRC32 { //nolint:gosec // io.Copy counts are never negative
		return name, nil, errors.New("size or checksum mismatch")
	}
	return name, buf.Bytes(), nil
}

// readDescriptor reads the data descriptor after an entry's data and returns its checksum; the signature is
// optional, the sizes have 8 bytes in a zip64 archive.
func readDescriptor(br *bufio.Reader, zip64 bool) (uint32, error) {
	var first uint32
	if err := binary.Read(br, binary.LittleEndian, &first); err != nil {
		return 0, unexpected(err)
	}
	crc := first
	if first == sigDataDescriptor {
		if err := binary.Read(br, binary.LittleEndian, &crc); err != nil {
			return 0, unexpected(err)
		}
	}
	sizes := 8
	if zip64 {
		sizes = 16
	}
	if _, err := br.Discard(sizes); err != nil {
		return 0, unexpected(err)
	}
	return crc, nil
}

// zip64Sizes reads the uncompressed and compressed size from the zip64 extra field.
func zip64Sizes(extra []byte) (size, compressed uint64, ok bool) {
	for len(extra) >= 4 {
		id, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if n > len(extra) {
			return 0, 0, false
		}
		if id == zip64ExtraID && n >= 16 {
			return binary.LittleEndian.Uint64(extra), binary.LittleEndian.Uint64(extra[8:]), true
		}
		extra = extra[n:]
	}
	return 0, 0, false
}

// unexpected turns the end of the input in the middle of the archive into io.ErrUnexpectedEOF: a truncated download
// is an error, never the end of the feed.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
