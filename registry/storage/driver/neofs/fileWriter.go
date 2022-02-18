package neofs

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/neofs/transformer"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/tzhash/tz"
)

type payloadChecksumHasher struct {
	hasher         hash.Hash
	checksumWriter func()
}

type writer struct {
	ctx    context.Context
	driver *driver
	path   string

	closed    bool
	committed bool
	cancelled bool

	maxSize        uint64
	buffer         []byte
	written        uint64
	splitInfo      *object.SplitInfo
	previous       []*oid.ID
	chunkWriter    io.Writer
	targetInit     func() transformer.ObjectTarget
	target         transformer.ObjectTarget
	current        *object.RawObject
	parent         *object.RawObject
	currentHashers []*payloadChecksumHasher
	parentHashers  []*payloadChecksumHasher
}

const tzChecksumSize = 64

// newSizeLimiterWriter creates new FileWriter that splits written payload to NeoFS objects with specific max size.
// MaxSize is taken from driver parameter.
func newSizeLimiterWriter(ctx context.Context, d *driver, path string, splitInfo *object.SplitInfo, parts []*object.Object) (storagedriver.FileWriter, error) {
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

	parent := d.rawObject(path)
	parentHashers, err := getParentHashers(parent, lastPart)
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
		parent: parent,
	}

	wrtr.current = fromObject(wrtr.parent)
	wrtr.current.InitRelations()
	wrtr.current.SetSplitID(splitInfo.SplitID())
	wrtr.initialize()

	return wrtr, nil
}

func getParentHashers(parent *object.RawObject, lastPart *object.Object) ([]*payloadChecksumHasher, error) {
	// if objects in split chain don't yet exist
	if lastPart == nil {
		hashers, err := payloadHashersForParentObject(parent, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("couldn't init empty parent hahsers: %w", err)
		}
		return hashers, nil
	}

	hashState, err := getSHAState(lastPart)
	if err != nil {
		return nil, err
	}

	hashers, err := payloadHashersForParentObject(parent, hashState, lastPart.PayloadHomomorphicHash().Sum())
	if err != nil {
		return nil, fmt.Errorf("couldn't init parent hahsers: %w", err)
	}
	return hashers, nil
}

func getSHAState(obj *object.Object) ([]byte, error) {
	var (
		err       error
		hashState []byte
	)

	for _, attr := range obj.Attributes() {
		if attr.Key() == attributeSHAState {
			if hashState, err = hex.DecodeString(attr.Value()); err != nil {
				return nil, fmt.Errorf("couldn't decode sha state '%s': %w", attr.Value(), err)
			}
			break
		}
	}
	if hashState == nil {
		return nil, fmt.Errorf("object '%s' has not sha state", obj.ID())
	}

	return hashState, nil
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
		writeHashes(w.parentHashers)
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
	// we have to copy chuck to prevent override when
	// next write happened but current object hasn't been put yet
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
		hashers[i].checksumWriter()
	}
}

func payloadHashersForObject(obj *object.RawObject) []*payloadChecksumHasher {
	return []*payloadChecksumHasher{
		newSHAChecksumHasher(obj, sha256.New(), false),
		newTZChecksumHasher(obj, tz.New()),
	}
}

func payloadHashersForParentObject(parent *object.RawObject, shaState []byte, tzPrev []byte) ([]*payloadChecksumHasher, error) {
	shaHash := sha256.New()
	if shaState != nil {
		unmarshaler, ok := shaHash.(encoding.BinaryUnmarshaler)
		if !ok {
			return nil, fmt.Errorf("sha256 must implement BinaryUnmarshaler")
		}
		if err := unmarshaler.UnmarshalBinary(shaState); err != nil {
			return nil, fmt.Errorf("could't unmarshal sha256 state")
		}
	}

	if tzPrev == nil {
		tzPrev = tz.New().Sum(nil)
	}

	return []*payloadChecksumHasher{
		newSHAChecksumHasher(parent, shaHash, true),
		newTZChecksumHasher(parent, tz.New(), tzPrev),
	}, nil
}

func newSHAChecksumHasher(obj *object.RawObject, shaHash hash.Hash, parent bool) *payloadChecksumHasher {
	return &payloadChecksumHasher{
		hasher: shaHash,
		checksumWriter: func() {
			setSHAHash(obj, shaHash.Sum(nil))
			// we don't want save sha state to parent object and last part
			if obj.Parent() == nil && !parent {
				setSHAState(obj, shaHash)
			}
		},
	}
}

func newTZChecksumHasher(obj *object.RawObject, tzHash hash.Hash, prevHash ...[]byte) *payloadChecksumHasher {
	return &payloadChecksumHasher{
		hasher: tzHash,
		checksumWriter: func() {
			sum := tzHash.Sum(nil)
			if len(prevHash) > 0 {
				var err error
				sum, err = tz.Concat(append(prevHash, sum))
				if err != nil {
					panic(fmt.Sprintf("couldn't concat tz hashes: %s", err.Error()))
				}
			}

			setTzHash(obj, sum)
		},
	}
}

func setTzHash(obj *object.RawObject, cs []byte) {
	if ln := len(cs); ln != tzChecksumSize {
		panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, tzChecksumSize))
	}

	csTZ := [tzChecksumSize]byte{}
	copy(csTZ[:], cs)

	sum := checksum.New()
	sum.SetTillichZemor(csTZ)
	obj.SetPayloadHomomorphicHash(sum)
}

func setSHAHash(obj *object.RawObject, cs []byte) {
	if ln := len(cs); ln != sha256.Size {
		panic(fmt.Sprintf("wrong checksum length: expected %d, has %d", ln, sha256.Size))
	}

	csSHA := [sha256.Size]byte{}
	copy(csSHA[:], cs)

	sum := checksum.New()
	sum.SetSHA256(csSHA)
	obj.SetPayloadChecksum(sum)
}

func setSHAState(obj *object.RawObject, shaHash hash.Hash) {
	marshaler, ok := shaHash.(encoding.BinaryMarshaler)
	if !ok {
		panic("expected sha256 is BinaryMarshaler")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("couldn't marshal sha256 state: %s", err.Error()))
	}

	attr := object.NewAttribute()
	attr.SetKey(attributeSHAState)
	attr.SetValue(hex.EncodeToString(state))
	obj.SetAttributes(attr)
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
