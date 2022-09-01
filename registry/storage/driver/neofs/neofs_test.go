package neofs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
	"time"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ctxValueUUIDKey = "vars.uuid"
	aioNodeEndpoint = "localhost:8080"
)

func params(walletPath string, containerID cid.ID) map[string]interface{} {
	return map[string]interface{}{
		paramWallet: map[interface{}]interface{}{
			paramPath:     walletPath,
			paramPassword: "",
		},
		paramPeers: map[interface{}]interface{}{
			0: map[interface{}]interface{}{
				paramAddress: aioNodeEndpoint,
			},
		},
		paramContainer: containerID.String(),
	}
}

func TestIntegration(t *testing.T) {
	f, err := os.CreateTemp("", "wallet")
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	defer func() {
		err = os.Remove(f.Name())
		require.NoError(t, err)
	}()

	// neofs-dev-env/wallets/wallet.json
	key, err := keys.NewPrivateKeyFromHex("1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb")
	require.NoError(t, err)

	var owner user.ID
	user.IDFromKey(&owner, key.PrivateKey.PublicKey)

	w, err := wallet.NewWallet(f.Name())
	require.NoError(t, err)

	acc := wallet.NewAccountFromPrivateKey(key)
	err = acc.Encrypt("", w.Scrypt)
	require.NoError(t, err)

	w.AddAccount(acc)
	err = w.Save()
	require.NoError(t, err)

	rootCtx := context.Background()
	aioImage := "nspccdev/neofs-aio-testcontainer:"
	versions := []string{
		"0.27.5",
		"0.28.1",
		"0.29.0",
		"latest",
	}

	for _, aioVersion := range versions {
		ctx, cancel := context.WithCancel(rootCtx)
		aioContainer := createDockerContainer(ctx, t, aioImage+aioVersion)

		sdkPool := getPool(ctx, t, key)
		cnrID := createContainer(ctx, t, sdkPool, owner)

		drvr, err := FromParameters(params(f.Name(), cnrID))
		require.NoError(t, err)

		drvrImpl := drvr.(*Driver).StorageDriver.(*driver)
		maxObjectSize := drvrImpl.maxSize

		t.Run("move "+aioVersion, func(t *testing.T) { testMove(ctx, t, drvr, aioVersion) })
		t.Run("set get content "+aioVersion, func(t *testing.T) { testSetContent(ctx, t, drvr, aioVersion) })
		t.Run("simple write "+aioVersion, func(t *testing.T) { testSimpleWrite(ctx, t, drvr, maxObjectSize, aioVersion) })
		t.Run("resume write "+aioVersion, func(t *testing.T) { testResumeWrite(ctx, t, drvr, maxObjectSize, aioVersion) })
		t.Run("write read "+aioVersion, func(t *testing.T) { testWriteRead(ctx, t, drvr, maxObjectSize, aioVersion) })
		t.Run("list "+aioVersion, func(t *testing.T) { testList(ctx, t, drvr, aioVersion) })
		t.Run("stat "+aioVersion, func(t *testing.T) { testStat(ctx, t, drvr, aioVersion) })

		err = aioContainer.Terminate(ctx)
		require.NoError(t, err)
		cancel()
	}
}

func formCtxAndPath(ctx context.Context, version string) (context.Context, string) {
	uid := uuid.NewString()
	ctx = context.WithValue(ctx, ctxValueUUIDKey, uid)
	path := "/test/file/" + version + "/" + uid

	return ctx, path
}

func testSetContent(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	content := []byte("test content")

	err := drvr.PutContent(ctx, path, content)
	require.NoError(t, err)

	data, err := drvr.GetContent(ctx, path)
	require.NoError(t, err)

	require.Equal(t, content, data)

	err = drvr.Delete(ctx, path)
	require.NoError(t, err)

	_, err = drvr.GetContent(ctx, path)
	require.Error(t, err)
}

func testMove(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	content := []byte("test content")

	err := drvr.PutContent(ctx, path, content)
	require.NoError(t, err)

	newPath := path + "/dest"

	err = drvr.Move(ctx, path, newPath)
	require.NoError(t, err)

	_, err = drvr.GetContent(ctx, path)
	require.Error(t, err)

	data, err := drvr.GetContent(ctx, newPath)
	require.NoError(t, err)

	require.Equal(t, content, data)
}

func testSimpleWrite(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, maxObjectSize uint64, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)
	writeAndCheck(ctx, t, drvr, maxObjectSize, path, false)
}

func testResumeWrite(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, maxObjectSize uint64, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	fileWriter, err := drvr.Writer(ctx, path, false)
	require.NoError(t, err)

	err = fileWriter.Close()
	require.NoError(t, err)

	writeAndCheck(ctx, t, drvr, maxObjectSize, path, true)
}

func testWriteRead(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, maxObjectSize uint64, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	fileWriter, err := drvr.Writer(ctx, path, false)
	require.NoError(t, err)

	dataSize := maxObjectSize + 1024
	data := make([]byte, dataSize)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = io.Copy(fileWriter, bytes.NewReader(data))
	require.NoError(t, err)

	err = fileWriter.Commit()
	require.NoError(t, err)

	fileReader, err := drvr.Reader(ctx, path, 0)
	require.NoError(t, err)

	buffer := make([]byte, dataSize/2)
	_, err = io.ReadFull(fileReader, buffer)
	require.NoError(t, err)
	require.Equal(t, data[:len(buffer)], buffer)

	err = fileReader.Close()
	require.NoError(t, err)

	fileReader, err = drvr.Reader(ctx, path, int64(len(buffer)))
	require.NoError(t, err)

	n, err := io.ReadFull(fileReader, buffer[:len(data)-len(buffer)])
	require.NoError(t, err)
	require.Equal(t, data[len(buffer):], buffer[:n])

	err = fileReader.Close()
	require.NoError(t, err)
}

func testList(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	fileWriter, err := drvr.Writer(ctx, path, false)
	require.NoError(t, err)

	dataSize := 4096
	data := make([]byte, dataSize)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = io.Copy(fileWriter, bytes.NewReader(data))
	require.NoError(t, err)

	err = fileWriter.Commit()
	require.NoError(t, err)

	res, err := drvr.List(ctx, path)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Contains(t, res, path)
}

func testStat(rootCtx context.Context, t *testing.T, drvr storagedriver.StorageDriver, version string) {
	ctx, path := formCtxAndPath(rootCtx, version)

	fileWriter, err := drvr.Writer(ctx, path, false)
	require.NoError(t, err)

	dataSize := 4096
	data := make([]byte, dataSize)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = io.Copy(fileWriter, bytes.NewReader(data))
	require.NoError(t, err)

	err = fileWriter.Commit()
	require.NoError(t, err)

	fi, err := drvr.Stat(ctx, path)
	require.NoError(t, err)
	require.False(t, fi.IsDir())
	require.Equal(t, path, fi.Path())

	fi, err = drvr.Stat(ctx, "/dummy")
	require.Error(t, err)

	fi, err = drvr.Stat(ctx, "/test/file/"+version)
	require.NoError(t, err)
	require.True(t, fi.IsDir())
	require.Equal(t, "/test/file/"+version, fi.Path())
}

func writeAndCheck(ctx context.Context, t *testing.T, drvr storagedriver.StorageDriver, maxObjectSize uint64, path string, append bool) {
	fileWriter, err := drvr.Writer(ctx, path, append)
	require.NoError(t, err)

	dataSize := maxObjectSize + 1024
	data := make([]byte, dataSize)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = io.Copy(fileWriter, bytes.NewReader(data))
	require.NoError(t, err)

	err = fileWriter.Commit()
	require.NoError(t, err)

	resData, err := drvr.GetContent(ctx, path)
	require.NoError(t, err)
	require.Equal(t, data, resData)
}

func createDockerContainer(ctx context.Context, t *testing.T, image string) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:       image,
		WaitingFor:  wait.NewLogStrategy("aio container started").WithStartupTimeout(30 * time.Second),
		Name:        "aio",
		Hostname:    "aio",
		NetworkMode: "host",
	}
	aioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	return aioC
}

func getPool(ctx context.Context, t *testing.T, key *keys.PrivateKey) *pool.Pool {
	var prm pool.InitParameters
	prm.SetKey(&key.PrivateKey)
	prm.SetNodeDialTimeout(5 * time.Second)
	prm.AddNode(pool.NewNodeParam(1, aioNodeEndpoint, 1))

	p, err := pool.NewPool(prm)
	require.NoError(t, err)

	err = p.Dial(ctx)
	require.NoError(t, err)

	return p
}

func createContainer(ctx context.Context, t *testing.T, clientPool *pool.Pool, owner user.ID) cid.ID {
	var policy netmap.PlacementPolicy
	err := policy.DecodeString("REP 1")
	require.NoError(t, err)

	var cnr container.Container
	cnr.Init()
	cnr.SetPlacementPolicy(policy)
	cnr.SetBasicACL(0x0FFFFFFF)
	cnr.SetOwner(owner)

	container.SetCreationTime(&cnr, time.Now())

	var wp pool.WaitParams
	wp.SetTimeout(30 * time.Second)
	wp.SetPollInterval(3 * time.Second)

	var prm pool.PrmContainerPut
	prm.SetContainer(cnr)

	cnrID, err := clientPool.PutContainer(ctx, prm)
	require.NoError(t, err)
	fmt.Println(cnrID.EncodeToString())

	return cnrID
}
