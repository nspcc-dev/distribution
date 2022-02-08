package neofs

import (
	"context"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	dcontext "github.com/distribution/distribution/v3/context"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/base"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/nspcc-dev/neo-go/cli/flags"
	rpc "github.com/nspcc-dev/neo-go/pkg/rpc/client"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	"github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/resolver"
)

const (
	driverName = "neofs"

	attributeFilePath        = "FilePath"
	attributeMultipartName   = "Distribution-MultipartName"
	attributeMultipartNumber = "Distribution-MultipartNumber"
	multipartInitPartPrefix  = "init-part-"
)

//DriverParameters is a struct that encapsulates all of the driver parameters after all values have been set
type DriverParameters struct {
	Endpoint    string
	ContainerID string
	Wallet      string
	Password    string

	Address           string
	ConnectionTimeout time.Duration
	RequestTimeout    time.Duration
	RebalanceInterval time.Duration
	SessionExpiration uint64
	RpcEndpoint       string
}

func init() {
	factory.Register(driverName, &neofsDriverFactory{})
}

type neofsDriverFactory struct{}

func (n *neofsDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	return FromParameters(parameters)
}

type driver struct {
	sdkPool     pool.Pool
	containerID *cid.ID
}

type baseEmbed struct {
	base.Base
}

// Driver is a storagedriver.StorageDriver implementation backed by NeoFS
// Objects are stored at absolute keys in the provided container.
type Driver struct {
	baseEmbed
}

// FromParameters constructs a new Driver with a given parameters map
// Required parameters:
// - endpoint
// - wallet
// - password
// Optional Parameters:
// - connection_timeout
// - request_timeout
// - rebalance_interval
// - session_expiration
// - rpc_endpoint
// - address
func FromParameters(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	endpoint := parameters["endpoint"]
	if endpoint == nil {
		return nil, fmt.Errorf("no edpoint provided")
	}

	wallet := parameters["wallet"]
	if wallet == nil {
		return nil, fmt.Errorf("no wallet provided")
	}

	password := parameters["password"]
	if password == nil {
		return nil, fmt.Errorf("no password provided")
	}

	containerID := parameters["container"]
	if containerID == nil {
		return nil, fmt.Errorf("no container provided")
	}

	address := parameters["address"]
	if address == nil {
		address = ""
	}

	rpcEndpoint := parameters["rpc_endpoint"]
	if rpcEndpoint == nil {
		rpcEndpoint = ""
	}

	connectionTimeout, err := parseTimeout(parameters, "connection_timeout", 4*time.Second)
	if err != nil {
		return nil, err
	}

	requestTimeout, err := parseTimeout(parameters, "request_timeout", 4*time.Second)
	if err != nil {
		return nil, err
	}

	rebalanceInterval, err := parseTimeout(parameters, "rebalance_interval", 30*time.Second)
	if err != nil {
		return nil, err
	}

	expiration, err := parseExpiration(parameters, "session_expiration", math.MaxUint64)
	if err != nil {
		return nil, err
	}

	params := DriverParameters{
		Endpoint:          fmt.Sprint(endpoint),
		ContainerID:       fmt.Sprint(containerID),
		Wallet:            fmt.Sprint(wallet),
		Password:          fmt.Sprint(password),
		Address:           fmt.Sprint(address),
		ConnectionTimeout: connectionTimeout,
		RequestTimeout:    requestTimeout,
		RebalanceInterval: rebalanceInterval,
		SessionExpiration: expiration,
		RpcEndpoint:       fmt.Sprint(rpcEndpoint),
	}

	return New(params)
}

func parseTimeout(parameters map[string]interface{}, name string, defaultValue time.Duration) (time.Duration, error) {
	timeoutValue := parameters[name]
	if timeoutValue == nil {
		return defaultValue, nil
	}

	if timeout, ok := timeoutValue.(time.Duration); ok {
		return timeout, nil
	}

	return 0, fmt.Errorf("invalid %s", name)
}

func parseExpiration(parameters map[string]interface{}, name string, defaultValue uint64) (uint64, error) {
	expirationValue := parameters[name]
	if expirationValue == nil {
		return defaultValue, nil
	}

	if expiration, ok := expirationValue.(uint64); ok {
		return expiration, nil
	}

	return 0, fmt.Errorf("invalid %s", name)
}

// New constructs a new Driver with the given NeoFS params
func New(params DriverParameters) (*Driver, error) {
	ctx := context.Background()

	sdkPool, err := createPool(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("couldn't create sdk pool: %w", err)
	}

	cnrID, err := getContainerID(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("couldn't get container id: %w", err)
	}

	d := &driver{
		sdkPool:     sdkPool,
		containerID: cnrID,
	}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}, nil
}

func getContainerID(ctx context.Context, params DriverParameters) (*cid.ID, error) {
	cnrID := cid.New()
	if err := cnrID.Parse(params.ContainerID); err == nil {
		return cnrID, nil
	}

	nnsResolver, err := createNnsResolver(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("couldn't create nns resolver: %w", err)
	}

	if cnrID, err = nnsResolver.ResolveContainerName(params.ContainerID); err != nil {
		return nil, fmt.Errorf("couldn't resolve container name '%s': %w", params.ContainerID, err)
	}

	return cnrID, nil
}

func createPool(ctx context.Context, param DriverParameters) (pool.Pool, error) {
	pb := new(pool.Builder)
	pb.AddNode(param.Endpoint, 1, 1)

	acc, err := getAccount(param)
	if err != nil {
		return nil, err
	}

	opts := &pool.BuilderOptions{
		Key:                     &acc.PrivateKey().PrivateKey,
		NodeConnectionTimeout:   param.ConnectionTimeout,
		NodeRequestTimeout:      param.RequestTimeout,
		ClientRebalanceInterval: param.RebalanceInterval,
		SessionExpirationEpoch:  param.SessionExpiration,
	}

	return pb.Build(ctx, opts)
}

func createNnsResolver(ctx context.Context, params DriverParameters) (resolver.NNSResolver, error) {
	if params.RpcEndpoint == "" {
		return nil, fmt.Errorf("empty rpc endpoind")
	}
	cli, err := rpc.New(ctx, params.RpcEndpoint, rpc.Options{})
	if err != nil {
		return nil, err
	}
	if err = cli.Init(); err != nil {
		return nil, err
	}

	return resolver.NewNNSResolver(cli)
}

func getAccount(param DriverParameters) (*wallet.Account, error) {
	w, err := wallet.NewWalletFromFile(param.Wallet)
	if err != nil {
		return nil, err
	}

	addr := w.GetChangeAddress()
	if param.Address != "" {
		addr, err = flags.ParseAddress(param.Address)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}
	acc := w.GetAccount(addr)
	err = acc.Decrypt(param.Password, w.Scrypt)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

func (d *driver) objectAddress(oid *oid.ID) *address.Address {
	addr := address.NewAddress()
	addr.SetContainerID(d.containerID)
	addr.SetObjectID(oid)
	return addr
}

func (d *driver) rawObject(path string) *object.RawObject {
	return d.formRawObject(map[string]string{
		object.AttributeFileName:  filepath.Base(path),
		attributeFilePath:         path,
		object.AttributeTimestamp: strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
}

func (d *driver) rawPartObject(path string, number int) *object.RawObject {
	return d.formRawObject(map[string]string{
		attributeMultipartName:    path,
		attributeMultipartNumber:  strconv.Itoa(number),
		object.AttributeTimestamp: strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
}

func (d *driver) rawInitPartObject(path string) *object.RawObject {
	return d.formRawObject(map[string]string{
		attributeMultipartName:    multipartInitPartPrefix + path,
		object.AttributeTimestamp: strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
}

func (d *driver) formRawObject(headers map[string]string) *object.RawObject {
	attributes := make([]*object.Attribute, 0, len(headers))

	for key, val := range headers {
		attr := object.NewAttribute()
		attr.SetKey(key)
		attr.SetValue(val)
		attributes = append(attributes, attr)
	}

	raw := object.NewRaw()
	raw.SetOwnerID(d.sdkPool.OwnerID())
	raw.SetContainerID(d.containerID)
	raw.SetAttributes(attributes...)

	return raw
}

func (d *driver) Name() string {
	return driverName
}

func (d *driver) GetContent(ctx context.Context, path string) ([]byte, error) {
	id, err := d.searchOne(ctx, path)
	if err != nil {
		return nil, err
	}

	p := new(client.GetObjectParams).WithAddress(d.objectAddress(id))
	obj, err := d.sdkPool.GetObject(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("couldn't get object '%s': %w", id, err)
	}

	return obj.Payload(), nil

}

func (d *driver) PutContent(ctx context.Context, path string, content []byte) error {
	if err := d.Delete(ctx, path); err != nil {
		return fmt.Errorf("couldn't delete '%s': %s", path, err)
	}

	rawObject := d.rawObject(path)
	rawObject.SetPayload(content)

	p := new(client.PutObjectParams).WithObject(rawObject.Object())
	if _, err := d.sdkPool.PutObject(ctx, p); err != nil {
		return fmt.Errorf("couldn't put object '%s': %w", path, err)
	}

	return nil
}

func (d *driver) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	id, err := d.searchOne(ctx, path)
	if err != nil {
		return nil, err
	}

	addr := d.objectAddress(id)

	p := new(client.ObjectHeaderParams).WithAddress(addr)
	obj, err := d.sdkPool.GetObjectHeader(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("couldn't head object '%s', id '%s': %w", path, id, err)
	}

	rng := object.NewRange()
	rng.SetOffset(uint64(offset))
	rng.SetLength(uint64(int64(obj.PayloadSize()) - offset))

	pr, pw := io.Pipe()
	go func() {
		dp := new(client.RangeDataParams).WithAddress(addr).WithRange(rng).WithDataWriter(pw)
		if _, err = d.sdkPool.ObjectPayloadRangeData(ctx, dp); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("couldn't get payload range of object '%s', id '%s': %w", path, id, err))
		}
		_ = pw.Close()
	}()

	return pr, nil
}

func (d *driver) Writer(ctx context.Context, path string, append bool) (storagedriver.FileWriter, error) {
	id, err := d.searchInitPart(ctx, path)
	if err != nil {
		if !append && isErrPathNotFound(err) {
			rawObject := d.rawInitPartObject(path)
			p := new(client.PutObjectParams).WithObject(rawObject.Object())
			id, err = d.sdkPool.PutObject(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("couldn't put init part object '%s': %w", path, err)
			}
			dcontext.GetLogger(ctx).Warnf("new writer init '%s'", path)
			return d.newWriter(ctx, path, id, nil), nil
		}
		return nil, fmt.Errorf("couldn't find init part for path '%s': %w", path, err)
	} else if !append {
		return nil, fmt.Errorf("init upload part '%s' already exist, id '%s'", path, id)
	}

	ids, err := d.searchParts(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("couldn't search parts '%s': %w", path, err)
	}

	objects := make([]*object.Object, len(ids))
	for i, id := range ids {
		p := new(client.ObjectHeaderParams).WithAddress(d.objectAddress(id))
		obj, err := d.sdkPool.GetObjectHeader(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("couldn't head object part '%s', id '%s': %w", path, id, err)
		}
		objects[i] = obj
	}
	dcontext.GetLogger(ctx).Warnf("new writer append '%s', objects %d", path, len(ids))
	return d.newWriter(ctx, path, id, objects), nil
}

func isErrPathNotFound(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case storagedriver.PathNotFoundError:
		return true
	}
	return false
}

func (d *driver) Stat(ctx context.Context, path string) (storagedriver.FileInfo, error) {
	if path == "/" {
		return newFileInfoDir(path), nil
	}

	ids, err := d.searchByPrefix(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("couldn't search objects '%s': %w", path, err)
	}

	if len(ids) > 0 {
		for _, id := range ids {
			p := new(client.ObjectHeaderParams).WithAddress(d.objectAddress(id))
			obj, err := d.sdkPool.GetObjectHeader(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("couldn't get object '%s': %w", id, err)
			}

			fileInf := newFileInfo(ctx, obj)
			if fileInf.Path() == path {
				return fileInf, nil
			}
		}
	}

	return newFileInfoDir(path), nil
}

func (d *driver) List(ctx context.Context, path string) ([]string, error) {
	ids, err := d.searchByPrefix(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("couldn't search by prefix '%s': %w", path, err)
	}

	result := make([]string, 0, len(ids))
	for _, id := range ids {
		p := new(client.ObjectHeaderParams).WithAddress(d.objectAddress(id))
		obj, err := d.sdkPool.GetObjectHeader(ctx, p)
		if err != nil {
			dcontext.GetLogger(ctx).Warnf("couldn't get list object '%s' in path '%s': %s", id, path, err)
			continue
		}

		fileInf := newFileInfo(ctx, obj)
		if filepath.Dir(fileInf.Path()) == path { //todo check trailing slash
			result = append(result, fileInf.Path())
		}
	}

	return result, nil
}

func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
	pr, pw := io.Pipe()

	sourceID, err := d.searchOne(ctx, sourcePath)
	if err != nil {
		return err
	}

	if err = d.Delete(ctx, destPath); err != nil {
		return fmt.Errorf("couldn't delete '%s' object:  %w", destPath, err)
	}

	go func() {
		p := new(client.GetObjectParams).WithAddress(d.objectAddress(sourceID)).WithPayloadWriter(pw)
		_, err = d.sdkPool.GetObject(ctx, p)
		if err = pw.CloseWithError(err); err != nil {
			dcontext.GetLogger(ctx).Errorf("could not get source object '%s' by oid '%s': %w", sourcePath, sourceID, err)
		}
	}()

	rawObj := d.rawObject(destPath)
	p := new(client.PutObjectParams).WithObject(rawObj.Object()).WithPayloadReader(pr)
	if _, err = d.sdkPool.PutObject(ctx, p); err != nil {
		return fmt.Errorf("couldn't put object '%s': %w", destPath, err)
	}

	dp := new(client.DeleteObjectParams).WithAddress(d.objectAddress(sourceID))
	if err = d.sdkPool.DeleteObject(ctx, dp); err != nil {
		return fmt.Errorf("couldn't remove source file '%s', id '%s': %w", sourcePath, sourceID, err)
	}

	return nil
}

func (d *driver) Delete(ctx context.Context, path string) error {
	ids, err := d.search(ctx, path)
	if err != nil {
		return fmt.Errorf("couldn't search '%s': %s", path, err)
	}

	for _, id := range ids {
		if err = d.delete(ctx, id); err != nil {
			return fmt.Errorf("couldn't delete object by path '%s': %w", path, err)
		}
	}
	return nil
}

func (d *driver) delete(ctx context.Context, id *oid.ID) error {
	p := new(client.DeleteObjectParams).WithAddress(d.objectAddress(id))
	if err := d.sdkPool.DeleteObject(ctx, p); err != nil {
		return fmt.Errorf("couldn't delete object '%s': %w", id, err)
	}

	return nil
}

func (d *driver) URLFor(_ context.Context, _ string, _ map[string]interface{}) (string, error) {
	return "", storagedriver.ErrUnsupportedMethod{DriverName: driverName}
}

func (d *driver) Walk(ctx context.Context, path string, fn storagedriver.WalkFn) error {
	ids, err := d.searchByPrefix(ctx, path)
	if err != nil {
		return fmt.Errorf("couldn't search by prefix for walk '%s': %w", path, err)
	}

	for _, id := range ids {
		p := new(client.ObjectHeaderParams).WithAddress(d.objectAddress(id))
		obj, err := d.sdkPool.GetObjectHeader(ctx, p)
		if err != nil {
			return fmt.Errorf("couldn't get object '%s': %w", id, err)
		}
		fileInf := newFileInfo(ctx, obj)
		if err = fn(fileInf); err != nil {
			return fmt.Errorf("walk fn error object '%s', id '%s': %w", fileInf.Path(), id, err)
		}
	}

	return nil
}

func (d *driver) search(ctx context.Context, path string) ([]*oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attributeFilePath, path, object.MatchStringEqual)

	p := new(client.SearchObjectParams).WithContainerID(d.containerID).WithSearchFilters(filters)
	return d.sdkPool.SearchObject(ctx, p)
}

func (d *driver) searchByPrefix(ctx context.Context, prefix string) ([]*oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attributeFilePath, prefix, object.MatchCommonPrefix)

	p := new(client.SearchObjectParams).WithContainerID(d.containerID).WithSearchFilters(filters)
	return d.sdkPool.SearchObject(ctx, p)
}

func (d *driver) searchParts(ctx context.Context, path string) ([]*oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attributeMultipartName, path, object.MatchStringEqual)

	p := new(client.SearchObjectParams).WithContainerID(d.containerID).WithSearchFilters(filters)
	return d.sdkPool.SearchObject(ctx, p)
}

func (d *driver) searchInitPart(ctx context.Context, path string) (*oid.ID, error) {
	path = multipartInitPartPrefix + path
	ids, err := d.searchParts(ctx, path)
	return handleSearchResponse(path, ids, err)
}

func (d *driver) searchOne(ctx context.Context, path string) (*oid.ID, error) {
	ids, err := d.search(ctx, path)
	return handleSearchResponse(path, ids, err)
}

func handleSearchResponse(path string, ids []*oid.ID, err error) (*oid.ID, error) {
	if err != nil {
		return nil, fmt.Errorf("couldn't search path '%s': %w", path, err)
	}

	if len(ids) == 0 {
		return nil, storagedriver.PathNotFoundError{
			Path:       path,
			DriverName: driverName,
		}
	}

	if len(ids) > 1 {
		return nil, fmt.Errorf("found %d objects by path '%s'", len(ids), path)
	}

	return ids[0], nil
}

type fileInfo struct {
	path    string
	size    int64
	modTime time.Time
	isDir   bool
}

func (f *fileInfo) Path() string {
	return f.path
}

func (f *fileInfo) Size() int64 {
	return f.size
}

func (f *fileInfo) ModTime() time.Time {
	return f.modTime
}

func (f *fileInfo) IsDir() bool {
	return f.isDir
}

func newFileInfo(ctx context.Context, obj *object.Object) *fileInfo {
	fileInf := &fileInfo{
		size: int64(obj.PayloadSize()),
	}

	for _, attr := range obj.Attributes() {
		switch attr.Key() {
		case attributeFilePath:
			fileInf.path = attr.Value()
		case object.AttributeTimestamp:
			timestamp, err := strconv.ParseInt(attr.Value(), 10, 64)
			if err != nil {
				dcontext.GetLogger(ctx).Warnf("object '%s' has invalid timestamp '%s'", obj.ID(), attr.Value())
				continue
			}
			fileInf.modTime = time.Unix(timestamp, 0)
		}
	}

	return fileInf
}

func newFileInfoDir(path string) *fileInfo {
	return &fileInfo{
		path:    path,
		modTime: time.Now(),
		isDir:   true,
	}
}

type partInfo struct {
	*fileInfo
	number string
	id     *oid.ID
}

func newPartInfo(ctx context.Context, obj *object.Object) *partInfo {
	part := &partInfo{
		fileInfo: newFileInfo(ctx, obj),
		id:       obj.ID(),
	}

	for _, attr := range obj.Attributes() {
		switch attr.Key() {
		case attributeMultipartNumber:
			part.number = attr.Value()
		case attributeMultipartName:
			part.path = attr.Value()
		}
	}

	return part
}

type putPartResult struct {
	id  *oid.ID
	err error
}

type writer struct {
	ctx            context.Context
	driver         *driver
	path           string
	size           int64
	initPartID     *oid.ID
	objects        []*object.Object
	nextObjWriter  io.WriteCloser
	putPartChannel chan *putPartResult

	closed    bool
	committed bool
	cancelled bool
}

func (d *driver) newWriter(ctx context.Context, path string, initPartID *oid.ID, objects []*object.Object) storagedriver.FileWriter {
	var size uint64
	for _, obj := range objects {
		size += obj.PayloadSize()
	}

	return &writer{
		ctx:        ctx,
		driver:     d,
		path:       path,
		size:       int64(size),
		objects:    objects,
		initPartID: initPartID,
	}
}

func (w *writer) Write(data []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("already closed")
	} else if w.committed {
		return 0, fmt.Errorf("already committed")
	} else if w.cancelled {
		return 0, fmt.Errorf("already cancelled")
	}

	if w.nextObjWriter == nil {
		pr, pw := io.Pipe()
		w.nextObjWriter = pw
		w.putPartChannel = make(chan *putPartResult)
		go func() {
			defer close(w.putPartChannel)

			rawObject := w.driver.rawPartObject(w.path, len(w.objects))
			p := new(client.PutObjectParams).WithObject(rawObject.Object()).WithPayloadReader(pr)
			res := new(putPartResult)
			res.id, res.err = w.driver.sdkPool.PutObject(w.ctx, p)
			w.putPartChannel <- res
		}()
	}

	n, err := w.nextObjWriter.Write(data)
	w.size += int64(n)
	return n, err
}

func (w *writer) Close() error {
	if w.closed {
		return fmt.Errorf("already closed")
	}
	w.closed = true
	dcontext.GetLogger(w.ctx).Warnf("closing writer '%s', objs %d, size %d", w.path, len(w.objects), w.size)
	if w.nextObjWriter != nil {
		if err := w.nextObjWriter.Close(); err != nil {
			return err
		}

		putPartRes := <-w.putPartChannel
		if putPartRes.err != nil {
			return putPartRes.err
		}

		ph := new(client.ObjectHeaderParams).WithAddress(w.driver.objectAddress(putPartRes.id))
		obj, err := w.driver.sdkPool.GetObjectHeader(w.ctx, ph)
		if err != nil {
			return fmt.Errorf("couldn't head part after put '%s', id '%s': %w", w.path, putPartRes.id, err)
		}
		w.objects = append(w.objects, obj)
	}
	return nil
}

func (w *writer) Size() int64 {
	return w.size
}

func (w *writer) Cancel() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	}
	w.cancelled = true

	return w.deleteParts()
}

func (w *writer) deleteParts() error {
	for _, obj := range w.objects {
		if err := w.driver.delete(w.ctx, obj.ID()); err != nil {
			return fmt.Errorf("couldn't delete object by path '%s': %w", w.path, err)
		}
	}

	if err := w.driver.delete(w.ctx, w.initPartID); err != nil {
		return fmt.Errorf("couldn't delete object by path '%s': %w", w.path, err)
	}

	return nil
}

func (w *writer) Commit() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	} else if w.cancelled {
		return fmt.Errorf("already cancelled")
	}
	w.committed = true
	if err := w.Close(); err != nil {
		return fmt.Errorf("couldn't close writer '%s': %w", w.path, err)
	}
	dcontext.GetLogger(w.ctx).Warnf("commiting '%s'", w.path)

	errCh := make(chan error)
	pr, pw := io.Pipe()

	go func() {
		rawObject := w.driver.rawObject(w.path)
		p := new(client.PutObjectParams).WithObject(rawObject.Object()).WithPayloadReader(pr)
		_, err := w.driver.sdkPool.PutObject(w.ctx, p)
		errCh <- err
		close(errCh)
	}()

	for _, id := range w.orderedParts() {
		p := new(client.GetObjectParams).WithAddress(w.driver.objectAddress(id)).WithPayloadWriter(pw)
		if _, err := w.driver.sdkPool.GetObject(w.ctx, p); err != nil {
			_ = pw.CloseWithError(err)
			return fmt.Errorf("couldn't commit object '%s' because of read from part '%s' fails: %w", w.path, id, err)
		}
	}
	_ = pw.Close()

	if err := <-errCh; err != nil {
		return fmt.Errorf("couldn't commit object '%s': %w", w.path, err)
	}
	return w.deleteParts()
}

func (w *writer) orderedParts() []*oid.ID {
	parts := make([]*partInfo, len(w.objects))
	for i, obj := range w.objects {
		parts[i] = newPartInfo(w.ctx, obj)
	}

	sort.Slice(parts, func(i, j int) bool {
		if parts[i].number == parts[j].number {
			return parts[i].modTime.Before(parts[j].modTime)
		}
		return parts[i].number < parts[j].number
	})

	ids := make([]*oid.ID, 0, len(parts))
	for _, part := range parts {
		ids = append(ids, part.id)
	}

	return ids
}

func (w *writer) updateObjects() error {
	ids, err := w.driver.searchParts(w.ctx, w.path)
	if err != nil {
		return fmt.Errorf("couldn't search parts '%s': %w", w.path, err)
	}

	var size uint64
	objects := make([]*object.Object, len(ids))
	for i, id := range ids {
		p := new(client.ObjectHeaderParams).WithAddress(w.driver.objectAddress(id))
		obj, err := w.driver.sdkPool.GetObjectHeader(w.ctx, p)
		if err != nil {
			return fmt.Errorf("couldn't head object part '%s', id '%s': %w", w.path, id, err)
		}
		objects[i] = obj
		size += obj.PayloadSize()
	}

	w.objects = objects
	w.size = int64(size)
	return nil
}
