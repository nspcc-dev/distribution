package neofs

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"fmt"
	"github.com/distribution/distribution/v3/registry/storage/driver/neofs/transformer"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/tzhash/tz"
	"hash"
	"io"
)

type payloadChecksumHasher struct {
	hasher hash.Hash

	checksumWriter func(hash.Hash)
}

type payloadChecksumParentHasher struct {
	hasher hash.Hash

	checksumWriter func(*object.RawObject, []byte)
}

const tzChecksumSize = 64

func NewSizeLimiterWriter(ctx context.Context, d *driver, path string, splitInfo *object.SplitInfo, parts []*object.Object) (*writer, error) {
	var (
		err      error
		size     uint64
		lastPart *object.Object
	)

	for _, obj := range parts {
		size += obj.PayloadSize()
		if obj.ID().Equal(splitInfo.LastPart()) {
			lastPart = obj
		}
	}

	parentHashers, err := getParentHashers(lastPart)
	if err != nil {
		return nil, err
	}

	wrtr := &writer{
		maxSize:       d.maxSize,
		buffer:        make([]byte, d.maxSize),
		ctx:           ctx,
		driver:        d,
		path:          path,
		written:       size,
		splitInfo:     splitInfo,
		previous:      formPreviousChain(splitInfo.LastPart(), parts),
		parentHashers: parentHashers,
		targetInit: func() transformer.ObjectTarget {
			return d.newObjTarget(ctx)

		},
		parent: d.rawObject(path),
	}

	wrtr.current = fromObject(wrtr.parent)
	wrtr.current.InitRelations()
	wrtr.current.SetSplitID(splitInfo.SplitID())
	wrtr.initialize()

	return wrtr, nil
}

func getParentHashers(lastPart *object.Object) ([]*payloadChecksumParentHasher, error) {
	if lastPart == nil {
		hashers, err := payloadHashersForParentObject(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("couldn't init empty parent hahsers: %w", err)
		}
		return hashers, nil
	}

	var (
		err       error
		hashState []byte
	)

	for _, attr := range lastPart.Attributes() {
		if attr.Key() == attributeSHAState {
			if hashState, err = hex.DecodeString(attr.Value()); err != nil {
				return nil, fmt.Errorf("couldn't decode sha state '%s': %w", attr.Value(), err)
			}
			break
		}
	}
	if hashState == nil {
		return nil, fmt.Errorf("last part has not sha state")
	}

	hashers, err := payloadHashersForParentObject(hashState, lastPart.PayloadHomomorphicHash().Sum())
	if err != nil {
		return nil, fmt.Errorf("couldn't init parent hahsers: %w", err)
	}
	return hashers, nil
}

func formPreviousChain(lastPartID *oid.ID, parts []*object.Object) []*oid.ID {
	previous := make([]*oid.ID, 0, len(parts))
	current := lastPartID
	for current != nil {
		previous = append([]*oid.ID{current}, previous...)
		for _, part := range parts {
			if current.Equal(part.ID()) {
				current = part.PreviousID()
				break
			}
		}
	}
	return previous
}

type writer struct {
	ctx    context.Context
	driver *driver
	path   string

	closed    bool
	committed bool
	cancelled bool

	maxSize         uint64
	written         uint64
	buffer          []byte
	splitInfo       *object.SplitInfo
	targetInit      func() transformer.ObjectTarget
	target          transformer.ObjectTarget
	current, parent *object.RawObject
	currentHashers  []*payloadChecksumHasher
	parentHashers   []*payloadChecksumParentHasher
	previous        []*oid.ID
	chunkWriter     io.Writer
}

func (w *writer) Write(data []byte) (int, error) {
	if err := w.checkState(); err != nil {
		return 0, err
	}

	if err := w.writeChunk(data); err != nil {
		return 0, err
	}

	return len(data), nil

}

func (w *writer) Close() error {
	if err := w.checkState(); err != nil {
		return err
	}
	w.closed = true

	_, err := w.release(false)
	return err
}

func (w *writer) Size() int64 {
	return int64(w.written)
}

func (w *writer) Cancel() error {
	if err := w.checkState(); err != nil {
		return err
	}
	w.cancelled = true

	return w.deleteParts()
}

func (w *writer) Commit() error {
	if err := w.checkState(); err != nil {
		return err
	}
	w.committed = true

	_, err := w.release(true)
	return err
}

func (w *writer) release(withParent bool) (*transformer.AccessIdentifiers, error) {
	if withParent {
		w.writeParentHashes()
		w.parent.SetPayloadSize(w.written)
		w.current.SetParent(w.parent.Object())
	}

	// release current object
	writeHashes(w.currentHashers)

	// release current, get its id
	if err := w.target.WriteHeader(w.current); err != nil {
		return nil, fmt.Errorf("could not write header: %w", err)
	}

	ids, err := w.target.Close()
	if err != nil {
		return nil, fmt.Errorf("could not close target: %w", err)
	}

	// save identifier of the released object
	w.previous = append(w.previous, ids.SelfID())

	if withParent {
		// generate and release linking object
		w.initializeLinking(ids.Parent())
		w.initializeCurrent()

		if _, err = w.release(false); err != nil {
			return nil, fmt.Errorf("could not release linking object: %w", err)
		}
	}

	return ids, nil
}

func (w *writer) initializeLinking(parHdr *object.Object) {
	w.current = fromObject(w.current)
	w.current.SetParent(parHdr)
	w.current.SetChildren(w.previous...)
}

func (w *writer) writeChunk(chunk []byte) error {
	// statement is true if the previous write of bytes reached exactly the boundary.
	if w.written > 0 && w.written%w.maxSize == 0 {
		// we need to release current object
		if _, err := w.release(false); err != nil {
			return fmt.Errorf("could not release object: %w", err)
		}

		// initialize another object
		w.initialize()
	}

	var (
		ln         = uint64(len(chunk))
		cut        = ln
		leftToEdge = w.maxSize - w.written%w.maxSize
	)

	// write bytes no further than the boundary of the current object
	if ln > leftToEdge {
		cut = leftToEdge
	}

	offset := w.written % w.maxSize
	_ = copy(w.buffer[offset:offset+cut], chunk[:cut])

	if _, err := w.chunkWriter.Write(w.buffer[offset : offset+cut]); err != nil {
		return fmt.Errorf("could not write chunk to target: %w", err)
	}

	// increase written bytes counter
	w.written += cut

	// if there are more bytes in buffer we call method again to start filling another object
	if ln > leftToEdge {
		return w.writeChunk(chunk[cut:])
	}

	return nil
}

func (w *writer) initialize() {
	if ln := len(w.previous); ln > 0 {
		// set previous object to the last previous identifier
		w.current.SetPreviousID(w.previous[ln-1])
	}

	w.initializeCurrent()
}

func (w *writer) initializeCurrent() {
	// initialize current object target
	w.target = w.targetInit()

	// create payload hashers
	w.currentHashers = payloadHashersForObject(w.current)

	// compose multi-writer from target and all payload hashers
	ws := make([]io.Writer, 0, 1+len(w.currentHashers)+len(w.parentHashers))

	ws = append(ws, w.target)

	for i := range w.currentHashers {
		ws = append(ws, w.currentHashers[i].hasher)
	}

	for i := range w.parentHashers {
		ws = append(ws, w.parentHashers[i].hasher)
	}

	w.chunkWriter = io.MultiWriter(ws...)
}

func fromObject(obj *object.RawObject) *object.RawObject {
	res := object.NewRaw()
	res.SetContainerID(obj.ContainerID())
	res.SetOwnerID(obj.OwnerID())
	res.SetType(obj.Type())
	res.SetSplitID(obj.SplitID())

	return res
}

func writeHashes(hashers []*payloadChecksumHasher) {
	for i := range hashers {
		hashers[i].checksumWriter(hashers[i].hasher)
	}
}

func payloadHashersForObject(obj *object.RawObject) []*payloadChecksumHasher {
	return []*payloadChecksumHasher{
		{
			hasher: sha256.New(),
			checksumWriter: func(shaHash hash.Hash) {
				cs := shaHash.Sum(nil)

				if ln := len(cs); ln != sha256.Size {
					panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, sha256.Size))
				}

				csSHA := [sha256.Size]byte{}
				copy(csSHA[:], cs)

				checksum := checksum.New()
				checksum.SetSHA256(csSHA)

				obj.SetPayloadChecksum(checksum)

				if obj.Parent() != nil {
					return
				}

				marshaler, ok := shaHash.(encoding.BinaryMarshaler)
				if !ok {
					panic("expected sha256 that is BinaryMarshaler")
				}
				state, err := marshaler.MarshalBinary()
				if err != nil {
					panic(fmt.Sprintf("couldn't marshal sha256 state: %s", err.Error()))
				}

				attr := object.NewAttribute()
				attr.SetKey(attributeSHAState)
				attr.SetValue(hex.EncodeToString(state))
				obj.SetAttributes(attr)
			},
		},
		{
			hasher: tz.New(),
			checksumWriter: func(tzHash hash.Hash) {
				cs := tzHash.Sum(nil)

				if ln := len(cs); ln != tzChecksumSize {
					panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, tzChecksumSize))
				}

				csTZ := [tzChecksumSize]byte{}
				copy(csTZ[:], cs)

				checksum := checksum.New()
				checksum.SetTillichZemor(csTZ)

				obj.SetPayloadHomomorphicHash(checksum)
			},
		},
	}
}

func payloadHashersForParentObject(shaState []byte, tzPrev []byte) ([]*payloadChecksumParentHasher, error) {
	sha := sha256.New()
	if shaState != nil {
		unmarshaler, ok := sha.(encoding.BinaryUnmarshaler)
		if !ok {
			return nil, fmt.Errorf("sha256 must implement BinaryUnmarshaler")
		}
		if err := unmarshaler.UnmarshalBinary(shaState); err != nil {
			return nil, fmt.Errorf("could't unmarshal sha256 state")
		}
	}

	prev := [][]byte{tzPrev}
	if tzPrev == nil {
		tzHash := tz.New()
		prev[0] = tzHash.Sum(nil)
	}

	return []*payloadChecksumParentHasher{
		{
			hasher: sha,
			checksumWriter: func(obj *object.RawObject, cs []byte) {
				if ln := len(cs); ln != sha256.Size {
					panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, sha256.Size))
				}

				csSHA := [sha256.Size]byte{}
				copy(csSHA[:], cs)

				checksum := checksum.New()
				checksum.SetSHA256(csSHA)

				obj.SetPayloadChecksum(checksum)
			},
		},
		{
			hasher: tz.New(),
			checksumWriter: func(obj *object.RawObject, cs []byte) {
				if ln := len(cs); ln != tzChecksumSize {
					panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, tzChecksumSize))
				}

				sum, err := tz.Concat(append(prev, cs))
				if err != nil {
					panic(fmt.Sprintf("couldn't concat tz hashes: %s", err.Error()))
				}

				csTZ := [tzChecksumSize]byte{}
				copy(csTZ[:], sum)

				checksum := checksum.New()
				checksum.SetTillichZemor(csTZ)

				obj.SetPayloadHomomorphicHash(checksum)
			},
		},
	}, nil
}

func (w *writer) checkState() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	} else if w.cancelled {
		return fmt.Errorf("already cancelled")
	}
	return nil
}

func (w *writer) deleteParts() error {
	for _, objID := range w.previous {
		if err := w.driver.delete(w.ctx, objID); err != nil {
			return fmt.Errorf("couldn't delete object by path '%s': %w", w.path, err)
		}
	}

	return nil
}

func (w *writer) writeParentHashes() {
	for i := range w.parentHashers {
		w.parentHashers[i].checksumWriter(w.parent, w.parentHashers[i].hasher.Sum(nil))
	}
}
