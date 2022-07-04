package neofs

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	dcontext "github.com/distribution/distribution/v3/context"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/base"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/distribution/distribution/v3/registry/storage/driver/neofs/transformer"
	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	resolver "github.com/nspcc-dev/neofs-sdk-go/ns"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
)

const (
	driverName = "neofs"

	attributeFilePath = "FilePath"
	attributeSHAState = "sha256state"
)

const (
	paramPeers                     = "peers"
	paramAddress                   = "address"
	paramWeight                    = "weight"
	paramPriority                  = "priority"
	paramWallet                    = "wallet"
	paramPath                      = "path"
	paramPassword                  = "password"
	paramContainer                 = "container"
	paramConnectionTimeout         = "connection_timeout"
	paramRequestTimeout            = "request_timeout"
	paramRebalanceInterval         = "rebalance_interval"
	paramSessionExpirationDuration = "session_expiration_duration"
	paramRpcEndpoint               = "rpc_endpoint"

	defaultConnectionTimeout         = 4 * time.Second
	defaultRequestTimeout            = 4 * time.Second
	defaultRebalanceInterval         = 20 * time.Second
	defaultSessionExpirationDuration = 100 // in epoch
)

//DriverParameters is a struct that encapsulates all of the driver parameters after all values have been set.
type DriverParameters struct {
	ContainerID               string
	Peers                     []*PeerInfo
	Wallet                    *Wallet
	ConnectionTimeout         time.Duration
	RequestTimeout            time.Duration
	RebalanceInterval         time.Duration
	SessionExpirationDuration uint64
	RpcEndpoint               string
}

// Wallet contains params to get key from wallet.
type Wallet struct {
	Path     string
	Password string
	Address  string
}

// PeerInfo contains node params.
type PeerInfo struct {
	Address  string
	Weight   float64
	Priority int
}

func init() {
	factory.Register(driverName, &neofsDriverFactory{})
}

type neofsDriverFactory struct{}

func (n *neofsDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	return FromParameters(parameters)
}

type driver struct {
	sdkPool     *pool.Pool
	owner       *user.ID
	key         *ecdsa.PrivateKey
	containerID cid.ID
	maxSize     uint64
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
// - peers
// - wallet
// Optional Parameters:
// - connection_timeout
// - request_timeout
// - rebalance_interval
// - session_expiration_duration
// - rpc_endpoint
func FromParameters(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	peers, err := parsePeers(parameters)
	if err != nil {
		return nil, err
	}

	walletInfo, err := parseWallet(parameters)
	if err != nil {
		return nil, err
	}

	containerID, ok := parameters[paramContainer].(string)
	if !ok {
		return nil, fmt.Errorf("no container provided")
	}

	var rpcEndpoint string
	rpcEndpointParam := parameters[paramRpcEndpoint]
	if rpcEndpointParam != nil {
		if rpcEndpoint, ok = rpcEndpointParam.(string); !ok {
			return nil, fmt.Errorf("invalid rpc_endpoint param")
		}
	}

	connectionTimeout, err := parseTimeout(parameters, paramConnectionTimeout, defaultConnectionTimeout)
	if err != nil {
		return nil, err
	}

	requestTimeout, err := parseTimeout(parameters, paramRequestTimeout, defaultRequestTimeout)
	if err != nil {
		return nil, err
	}

	rebalanceInterval, err := parseTimeout(parameters, paramRebalanceInterval, defaultRebalanceInterval)
	if err != nil {
		return nil, err
	}

	expiration, err := parseUInt64(parameters, paramSessionExpirationDuration, defaultSessionExpirationDuration)
	if err != nil {
		return nil, err
	}

	params := DriverParameters{
		Peers:                     peers,
		ContainerID:               containerID,
		Wallet:                    walletInfo,
		ConnectionTimeout:         connectionTimeout,
		RequestTimeout:            requestTimeout,
		RebalanceInterval:         rebalanceInterval,
		SessionExpirationDuration: expiration,
		RpcEndpoint:               rpcEndpoint,
	}

	return New(params)
}

func parseWallet(parameters map[string]interface{}) (*Wallet, error) {
	walletInfo := new(Wallet)

	walletParams, ok := parameters[paramWallet].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("no wallet params provided")
	}

	walletInfo.Path, ok = walletParams[paramPath].(string)
	if !ok {
		return nil, fmt.Errorf("no path provided")
	}

	walletInfo.Password, ok = walletParams[paramPassword].(string)
	if !ok {
		return nil, fmt.Errorf("no password provided")
	}

	addressParam := walletParams[paramAddress]
	if addressParam != nil {
		if walletInfo.Address, ok = addressParam.(string); !ok {
			return nil, fmt.Errorf("invalid address param")
		}
	}

	return walletInfo, nil
}

func parsePeers(parameters map[string]interface{}) ([]*PeerInfo, error) {
	poolParams, ok := parameters[paramPeers].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("no peers params provided")
	}

	var peers []*PeerInfo
	for _, val := range poolParams {
		peerInfo, ok := val.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid peers params")
		}

		peer := new(PeerInfo)

		peer.Address, ok = peerInfo[paramAddress].(string)
		if !ok {
			return nil, fmt.Errorf("invalid peer address")
		}

		weightParam := peerInfo[paramWeight]
		if weightParam != nil {
			switch weight := weightParam.(type) {
			case int:
				peer.Weight = float64(weight)
			case float64:
				peer.Weight = weight
			default:
				return nil, fmt.Errorf("invalid weight param")
			}
			if peer.Weight <= 0 {
				peer.Weight = 1
			}
		}

		priorityParam := peerInfo[paramPriority]
		if priorityParam != nil {
			if peer.Priority, ok = priorityParam.(int); !ok {
				return nil, fmt.Errorf("invalid priority param")
			} else if peer.Priority <= 0 {
				peer.Priority = 1
			}
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

func parseTimeout(parameters map[string]interface{}, name string, defaultValue time.Duration) (time.Duration, error) {
	timeoutValue := parameters[name]
	if timeoutValue == nil {
		return defaultValue, nil
	}

	switch val := timeoutValue.(type) {
	case int:
		return time.Duration(val), nil
	case int64:
		return time.Duration(val), nil
	case string:
		timeout, err := time.ParseDuration(val)
		if err != nil {
			return 0, fmt.Errorf("couldn't parse duration '%s': %w", val, err)
		}
		return timeout, nil
	}

	return 0, fmt.Errorf("invalid %s", name)
}

func parseUInt64(parameters map[string]interface{}, name string, defaultValue uint64) (uint64, error) {
	expirationValue := parameters[name]
	if expirationValue == nil {
		return defaultValue, nil
	}

	switch val := expirationValue.(type) {
	case int:
		return uint64(val), nil
	case int64:
		return uint64(val), nil
	}

	return 0, fmt.Errorf("invalid %s", name)
}

// New constructs a new Driver with the given NeoFS params
func New(params DriverParameters) (*Driver, error) {
	ctx := context.Background()

	acc, err := getAccount(params.Wallet)
	if err != nil {
		return nil, err
	}

	var owner user.ID
	user.IDFromKey(&owner, acc.PrivateKey().PrivateKey.PublicKey)

	sdkPool, err := createPool(ctx, acc, params)
	if err != nil {
		return nil, fmt.Errorf("couldn't create sdk pool: %w", err)
	}

	maxObjectSize, err := getMaxObjectSize(ctx, sdkPool)
	if err != nil {
		return nil, fmt.Errorf("couldn't get max object size: %w", err)
	}

	cnrID, err := getContainerID(params)
	if err != nil {
		return nil, fmt.Errorf("couldn't get container id: %w", err)
	}

	d := &driver{
		sdkPool:     sdkPool,
		owner:       &owner,
		key:         &acc.PrivateKey().PrivateKey,
		containerID: cnrID,
		maxSize:     maxObjectSize,
	}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}, nil
}

func getMaxObjectSize(ctx context.Context, sdkPool *pool.Pool) (uint64, error) {
	networkInfo, err := sdkPool.NetworkInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("couldn't get connection: %w", err)
	}

	maxObjectSize := networkInfo.MaxObjectSize()

	if maxObjectSize == 0 {
		return 0, fmt.Errorf("max object size must not be zero")
	}

	return maxObjectSize, nil
}

func getContainerID(params DriverParameters) (cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ContainerID); err == nil {
		return cnrID, nil
	}

	nnsResolver, err := createNnsResolver(params)
	if err != nil {
		return cid.ID{}, fmt.Errorf("couldn't create nns resolver: %w", err)
	}

	if cnrID, err = nnsResolver.ResolveContainerName(params.ContainerID); err != nil {
		return cid.ID{}, fmt.Errorf("couldn't resolve container name '%s': %w", params.ContainerID, err)
	}

	return cnrID, nil
}

func createPool(ctx context.Context, acc *wallet.Account, param DriverParameters) (*pool.Pool, error) {
	var prm pool.InitParameters
	prm.SetKey(&acc.PrivateKey().PrivateKey)
	prm.SetNodeDialTimeout(param.ConnectionTimeout)
	prm.SetHealthcheckTimeout(param.RequestTimeout)
	prm.SetClientRebalanceInterval(param.RebalanceInterval)
	prm.SetSessionExpirationDuration(param.SessionExpirationDuration)

	for _, peer := range param.Peers {
		prm.AddNode(pool.NewNodeParam(peer.Priority, peer.Address, peer.Weight))
	}

	p, err := pool.NewPool(prm)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err = p.Dial(ctx); err != nil {
		return nil, fmt.Errorf("dial pool: %w", err)
	}

	return p, nil
}

func createNnsResolver(params DriverParameters) (*resolver.NNS, error) {
	if params.RpcEndpoint == "" {
		return nil, fmt.Errorf("empty rpc endpoind")
	}

	var nns resolver.NNS
	if err := nns.Dial(params.RpcEndpoint); err != nil {
		return nil, fmt.Errorf("dial nns resolver: %w", err)
	}

	return &nns, nil
}

func getAccount(walletInfo *Wallet) (*wallet.Account, error) {
	w, err := wallet.NewWalletFromFile(walletInfo.Path)
	if err != nil {
		return nil, err
	}

	addr := w.GetChangeAddress()
	if walletInfo.Address != "" {
		addr, err = flags.ParseAddress(walletInfo.Address)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}
	acc := w.GetAccount(addr)
	err = acc.Decrypt(walletInfo.Password, w.Scrypt)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

func (d *driver) objectAddress(objID oid.ID) oid.Address {
	var addr oid.Address
	addr.SetContainer(d.containerID)
	addr.SetObject(objID)
	return addr
}

func (d *driver) formObject(path string) *object.Object {
	attrFilePath := object.NewAttribute()
	attrFilePath.SetKey(attributeFilePath)
	attrFilePath.SetValue(path)

	attrFileName := object.NewAttribute()
	attrFileName.SetKey(object.AttributeFileName)
	attrFileName.SetValue(filepath.Base(path))

	attrTimestamp := object.NewAttribute()
	attrTimestamp.SetKey(object.AttributeTimestamp)
	attrTimestamp.SetValue(strconv.FormatInt(time.Now().UTC().Unix(), 10))

	obj := object.New()
	obj.SetOwnerID(d.owner)
	obj.SetContainerID(d.containerID)
	obj.SetAttributes(*attrFilePath, *attrFileName, *attrTimestamp)

	return obj
}

func (d *driver) Name() string {
	return driverName
}

func (d *driver) GetContent(ctx context.Context, path string) ([]byte, error) {
	id, err := d.searchOne(ctx, path)
	if err != nil {
		return nil, err
	}

	var prm pool.PrmObjectGet
	prm.SetAddress(d.objectAddress(id))

	obj, err := d.sdkPool.GetObject(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("couldn't get object '%s': %w", id, err)
	}

	return io.ReadAll(obj.Payload)
}

func (d *driver) PutContent(ctx context.Context, path string, content []byte) error {
	if err := d.Delete(ctx, path); err != nil {
		return fmt.Errorf("couldn't delete '%s': %s", path, err)
	}

	obj := d.formObject(path)
	obj.SetPayload(content)

	var prm pool.PrmObjectPut
	prm.SetHeader(*obj)

	if _, err := d.sdkPool.PutObject(ctx, prm); err != nil {
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

	var prmHead pool.PrmObjectHead
	prmHead.SetAddress(addr)

	obj, err := d.sdkPool.HeadObject(ctx, prmHead)
	if err != nil {
		return nil, fmt.Errorf("couldn't head object '%s', id '%s': %w", path, id, err)
	}

	if uint64(offset) >= obj.PayloadSize() {
		return nil, fmt.Errorf("invalid offset %d for object length %d", offset, obj.PayloadSize())
	}

	length := obj.PayloadSize() - uint64(offset)

	var prmRange pool.PrmObjectRange
	prmRange.SetAddress(addr)
	prmRange.SetOffset(uint64(offset))
	prmRange.SetLength(length)

	res, err := d.sdkPool.ObjectRange(ctx, prmRange)
	if err != nil {
		return nil, fmt.Errorf("couldn't get payload range of object '%s', offset %d, length %d, id '%s': %w",
			path, offset, length, id, err)
	}

	return res, nil
}

func getUploadUUID(ctx context.Context) (uuid string) {
	return dcontext.GetStringValue(ctx, "vars.uuid")
}

func (d *driver) Writer(ctx context.Context, path string, append bool) (storagedriver.FileWriter, error) {
	splitID := object.NewSplitID()
	uploadUUID := getUploadUUID(ctx)
	if err := splitID.Parse(uploadUUID); err != nil {
		return nil, fmt.Errorf("couldn't parse split id as upload uuid '%s': %w", uploadUUID, err)
	}

	parts, noChild, err := d.headSplitParts(ctx, splitID, path, append)
	if err != nil {
		return nil, fmt.Errorf("couldn't search split parts '%s': %w", path, err)
	}

	splitInfo := object.NewSplitInfo()
	splitInfo.SetSplitID(splitID)

	for _, obj := range parts {
		if obj.Parent() != nil {
			return nil, fmt.Errorf("object already exist '%s'", path)
		}

		prevID, _ := obj.PreviousID()
		delete(noChild, prevID)
	}

	if len(noChild) > 1 {
		return nil, fmt.Errorf("couldn't find last part '%s'", path)
	}

	for lastPartID := range noChild {
		splitInfo.SetLastPart(lastPartID)
		break
	}

	wrtr, err := newSizeLimiterWriter(ctx, d, path, splitInfo, parts)
	if err != nil {
		return nil, fmt.Errorf("couldn't init size limiter writer: %w", err)
	}

	return wrtr, nil
}

func (d *driver) Stat(ctx context.Context, path string) (storagedriver.FileInfo, error) {
	if path == "/" { // healthcheck
		if _, err := d.sdkPool.NetworkInfo(ctx); err != nil {
			return nil, fmt.Errorf("healthcheck failed: %w", err)
		}
		return newFileInfoDir(path), nil
	}

	id, ok, err := d.searchOneBase(ctx, path, true)
	if err != nil {
		return nil, err
	}

	// assume there is not object with directory name
	// e.g. if file '/a/b/c' exists, files '/a/b' and '/a' don't
	if !ok {
		return newFileInfoDir(path), nil
	}

	var prm pool.PrmObjectHead
	prm.SetAddress(d.objectAddress(id))

	obj, err := d.sdkPool.HeadObject(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("couldn't get head object '%s': %w", id, err)
	}

	fileInfo := newFileInfo(ctx, obj, "")

	// e.g. search '/a/b' but because of prefix search we found '/a/b/c'
	// so we should return directory
	if fileInfo.Path() != path {
		return newFileInfoDir(path), nil
	}

	return fileInfo, nil
}

func (d *driver) List(ctx context.Context, path string) ([]string, error) {
	ids, err := d.searchByPrefix(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("couldn't search by prefix '%s': %w", path, err)
	}

	added := make(map[string]bool)

	result := make([]string, 0, len(ids))
	for _, id := range ids {
		var prm pool.PrmObjectHead
		prm.SetAddress(d.objectAddress(id))

		obj, err := d.sdkPool.HeadObject(ctx, prm)
		if err != nil {
			dcontext.GetLogger(ctx).Warnf("couldn't get list object '%s' in path '%s': %s", id, path, err)
			continue
		}

		fileInf := newFileInfo(ctx, obj, path)
		if !added[fileInf.Path()] {
			result = append(result, fileInf.Path())
			added[fileInf.Path()] = true
		}
	}

	sort.Strings(result)
	return result, nil
}

func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
	sourceID, err := d.searchOne(ctx, sourcePath)
	if err != nil {
		return err
	}

	if err = d.Delete(ctx, destPath); err != nil {
		return fmt.Errorf("couldn't delete '%s' object:  %w", destPath, err)
	}

	sourceAddr := d.objectAddress(sourceID)

	var prmGet pool.PrmObjectGet
	prmGet.SetAddress(sourceAddr)

	obj, err := d.sdkPool.GetObject(ctx, prmGet)
	if err != nil {
		return fmt.Errorf("could not get source object '%s' by oid '%s': %w", sourcePath, sourceID, err)
	}
	defer func() {
		if err = obj.Payload.Close(); err != nil {
			dcontext.GetLogger(ctx).Errorf("couldn't close object payload reader, path '%s' by oid '%s': %s",
				sourcePath, sourceID, err.Error())
		}
	}()

	objHeader := d.formObject(destPath)
	var prmPut pool.PrmObjectPut
	prmPut.SetHeader(*objHeader)
	prmPut.SetPayload(obj.Payload)

	if _, err = d.sdkPool.PutObject(ctx, prmPut); err != nil {
		return fmt.Errorf("couldn't put object '%s': %w", destPath, err)
	}

	var prmDelete pool.PrmObjectDelete
	prmDelete.SetAddress(sourceAddr)

	if err = d.sdkPool.DeleteObject(ctx, prmDelete); err != nil {
		return fmt.Errorf("couldn't remove source file '%s', id '%s': %w", sourcePath, sourceID, err)
	}

	return nil
}

func (d *driver) Delete(ctx context.Context, path string) error {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attributeFilePath, path, object.MatchStringEqual)

	var prmSearch pool.PrmObjectSearch
	prmSearch.SetContainerID(d.containerID)
	prmSearch.SetFilters(filters)

	res, err := d.sdkPool.SearchObjects(ctx, prmSearch)
	if err != nil {
		return fmt.Errorf("init searching using client: %w", err)
	}

	defer res.Close()

	var inErr error
	err = res.Iterate(func(id oid.ID) bool {
		if err = d.delete(ctx, id); err != nil {
			inErr = fmt.Errorf("couldn't delete object by path '%s': %w", path, err)
			return true
		}
		return false
	})
	if err == nil {
		err = inErr
	}
	if err != nil {
		return fmt.Errorf("iterate objects: %w", err)
	}

	return nil
}

func (d *driver) delete(ctx context.Context, id oid.ID) error {
	var prm pool.PrmObjectDelete
	prm.SetAddress(d.objectAddress(id))
	if err := d.sdkPool.DeleteObject(ctx, prm); err != nil {
		return fmt.Errorf("couldn't delete object '%s': %w", id, err)
	}

	return nil
}

func (d *driver) URLFor(_ context.Context, _ string, _ map[string]interface{}) (string, error) {
	return "", storagedriver.ErrUnsupportedMethod{DriverName: driverName}
}

func (d *driver) Walk(ctx context.Context, path string, fn storagedriver.WalkFn) error {
	return storagedriver.WalkFallback(ctx, d, path, fn)
}

func (d *driver) searchByPrefix(ctx context.Context, prefix string) ([]oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attributeFilePath, prefix, object.MatchCommonPrefix)

	return d.baseSearch(ctx, filters)
}

func (d *driver) headSplitParts(ctx context.Context, splitID *object.SplitID, path string, isAppend bool) ([]*object.Object, map[oid.ID]struct{}, error) {
	filters := object.NewSearchFilters()
	filters.AddPhyFilter()
	filters.AddSplitIDFilter(object.MatchStringEqual, splitID)

	var prm pool.PrmObjectSearch
	prm.SetContainerID(d.containerID)
	prm.SetFilters(filters)

	res, err := d.sdkPool.SearchObjects(ctx, prm)
	if err != nil {
		return nil, nil, fmt.Errorf("init searching using client: %w", err)
	}

	defer res.Close()

	var addr oid.Address
	addr.SetContainer(d.containerID)

	var inErr error
	var prmHead pool.PrmObjectHead

	var objects []*object.Object
	noChild := make(map[oid.ID]struct{})

	err = res.Iterate(func(id oid.ID) bool {
		addr.SetObject(id)
		prmHead.SetAddress(addr)

		obj, err := d.sdkPool.HeadObject(ctx, prmHead)
		if err != nil {
			inErr = fmt.Errorf("couldn't head object part '%s', id '%s', splitID '%s': %w", path, id, splitID, err)
			return true
		}

		if isAppend {
			objects = append(objects, obj)
			noChild[id] = struct{}{}
			return false
		}

		inErr = fmt.Errorf("init upload part '%s' already exist, splitID '%s'", path, splitID)
		return true
	})
	if err == nil {
		err = inErr
	}
	if err != nil {
		return nil, nil, fmt.Errorf("iterate objects: %w", err)
	}

	return objects, noChild, nil
}

func (d *driver) baseSearch(ctx context.Context, filters object.SearchFilters) ([]oid.ID, error) {
	var prm pool.PrmObjectSearch
	prm.SetContainerID(d.containerID)
	prm.SetFilters(filters)

	res, err := d.sdkPool.SearchObjects(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("init searching using client: %w", err)
	}

	defer res.Close()

	var buf []oid.ID

	err = res.Iterate(func(id oid.ID) bool {
		buf = append(buf, id)
		return false
	})
	if err != nil {
		return nil, fmt.Errorf("iterate objects: %w", err)
	}

	return buf, nil
}

func (d *driver) searchOne(ctx context.Context, path string) (oid.ID, error) {
	id, ok, err := d.searchOneBase(ctx, path, false)
	if err != nil {
		return oid.ID{}, err
	}

	if !ok {
		return oid.ID{}, fmt.Errorf("found more than one object by path '%s'", path)
	}

	return id, nil
}

func (d *driver) searchOneBase(ctx context.Context, path string, byPrefix bool) (resID oid.ID, ok bool, err error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	if byPrefix {
		filters.AddFilter(attributeFilePath, path, object.MatchCommonPrefix)
	} else {
		filters.AddFilter(attributeFilePath, path, object.MatchStringEqual)
	}

	var prm pool.PrmObjectSearch
	prm.SetContainerID(d.containerID)
	prm.SetFilters(filters)

	res, err := d.sdkPool.SearchObjects(ctx, prm)
	if err != nil {
		return oid.ID{}, false, fmt.Errorf("init searching using client: %w", err)
	}

	defer res.Close()

	var found bool
	err = res.Iterate(func(id oid.ID) bool {
		if found {
			ok = false
			return true
		}
		found = true
		resID = id
		ok = true
		return false
	})
	if err != nil {
		return oid.ID{}, false, fmt.Errorf("iterate objects by path '%s': %w", path, err)
	}

	if !found {
		return oid.ID{}, false, storagedriver.PathNotFoundError{Path: path, DriverName: driverName}
	}

	return resID, ok, nil
}

func newFileInfo(ctx context.Context, obj *object.Object, prefix string) storagedriver.FileInfo {
	fileInfoFields := storagedriver.FileInfoFields{
		Size: int64(obj.PayloadSize()),
	}

	for _, attr := range obj.Attributes() {
		switch attr.Key() {
		case attributeFilePath:
			fileInfoFields.Path = attr.Value()
		case object.AttributeTimestamp:
			timestamp, err := strconv.ParseInt(attr.Value(), 10, 64)
			if err != nil {
				objID, _ := obj.ID()
				dcontext.GetLogger(ctx).Warnf("object '%s' has invalid timestamp '%s'", objID.EncodeToString(), attr.Value())
				continue
			}
			fileInfoFields.ModTime = time.Unix(timestamp, 0)
		}
	}

	if len(prefix) > 0 {
		tail := strings.TrimPrefix(fileInfoFields.Path, prefix)
		if len(tail) > 0 {
			index := strings.Index(tail[1:], "/")
			if index >= 0 {
				fileInfoFields.IsDir = true
				fileInfoFields.Path = prefix + tail[:index+1]
			}
		}
	}

	return storagedriver.FileInfoInternal{FileInfoFields: fileInfoFields}
}

func newFileInfoDir(path string) storagedriver.FileInfo {
	return storagedriver.FileInfoInternal{
		FileInfoFields: storagedriver.FileInfoFields{
			Path:    path,
			ModTime: time.Now(),
			IsDir:   true,
		},
	}
}

func (d *driver) newObjTarget(ctx context.Context) transformer.ObjectTarget {
	return &objTarget{
		ctx:     ctx,
		sdkPool: d.sdkPool,
		key:     d.key,
	}
}

type objTarget struct {
	ctx     context.Context
	sdkPool *pool.Pool
	key     *ecdsa.PrivateKey
	obj     *object.Object
	chunks  [][]byte
}

func (t *objTarget) WriteHeader(obj *object.Object) error {
	t.obj = obj
	return nil
}

func (t *objTarget) Write(p []byte) (n int, err error) {
	t.chunks = append(t.chunks, p)
	return len(p), nil
}

func (t *objTarget) Close() (*transformer.AccessIdentifiers, error) {
	networkInfo, err := t.sdkPool.NetworkInfo(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't get network info: %w", err)
	}

	sz := 0
	for i := range t.chunks {
		sz += len(t.chunks[i])
	}

	ver := version.Current()
	currEpoch := networkInfo.CurrentEpoch()

	t.obj.SetPayloadSize(uint64(sz))
	t.obj.SetVersion(&ver)
	t.obj.SetCreationEpoch(currEpoch)

	var (
		parID  oid.ID
		parHdr *object.Object
	)

	if par := t.obj.Parent(); par != nil && par.Signature() == nil {
		objPar := object.NewFromV2(par.ToV2())

		objPar.SetCreationEpoch(currEpoch)

		if err := object.SetIDWithSignature(*t.key, objPar); err != nil {
			return nil, fmt.Errorf("could not finalize parent object: %w", err)
		}

		parID, _ = objPar.ID()

		t.obj.SetParent(objPar)
	}

	if err = object.SetIDWithSignature(*t.key, t.obj); err != nil {
		return nil, fmt.Errorf("could not finalize object: %w", err)
	}

	payload := make([]byte, 0, sz)
	for i := range t.chunks {
		payload = append(payload, t.chunks[i]...)
	}
	t.obj.SetPayload(payload)

	var prm pool.PrmObjectPut
	prm.SetHeader(*t.obj)

	_, err = t.sdkPool.PutObject(t.ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("couldn't put part: %w", err)
	}

	objID, _ := t.obj.ID()

	return new(transformer.AccessIdentifiers).
		WithSelfID(objID).
		WithParentID(&parID).
		WithParent(parHdr), nil
}
