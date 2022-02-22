package neofs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ctxValueUUIDKey = "vars.uuid"
	aioNodeEndpoint = "localhost:8080"
)

func params(walletPath string, containerID *cid.ID) map[string]interface{} {
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
	versions := []string{"0.27.5", "latest"}

	for _, version := range versions {
		ctx, cancel := context.WithCancel(rootCtx)
		aioContainer := createDockerContainer(ctx, t, aioImage+version)

		sdkPool := getPool(ctx, t, key)
		CID := createContainer(ctx, t, sdkPool)

		drvr, err := FromParameters(params(f.Name(), CID))
		require.NoError(t, err)

		drvrImpl := drvr.(*Driver).StorageDriver.(*driver)
		maxObjectSize := drvrImpl.maxSize

		t.Run("move "+version, func(t *testing.T) { testMove(ctx, t, drvr, version) })
		t.Run("set get content "+version, func(t *testing.T) { testSetContent(ctx, t, drvr, version) })
		t.Run("simple write "+version, func(t *testing.T) { testSimpleWrite(ctx, t, drvr, maxObjectSize, version) })
		t.Run("resume write "+version, func(t *testing.T) { testResumeWrite(ctx, t, drvr, maxObjectSize, version) })
		t.Run("write read "+version, func(t *testing.T) { testWriteRead(ctx, t, drvr, maxObjectSize, version) })

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

func getPool(ctx context.Context, t *testing.T, key *keys.PrivateKey) pool.Pool {
	pb := new(pool.Builder)
	pb.AddNode(aioNodeEndpoint, 1, 1)

	opts := &pool.BuilderOptions{
		Key:                   &key.PrivateKey,
		NodeConnectionTimeout: 5 * time.Second,
		NodeRequestTimeout:    5 * time.Second,
	}
	clientPool, err := pb.Build(ctx, opts)
	require.NoError(t, err)
	return clientPool
}

func createContainer(ctx context.Context, t *testing.T, clientPool pool.Pool) *cid.ID {
	pp, err := policy.Parse("REP 1")
	require.NoError(t, err)

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(0x0FFFFFFF),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))
	cnr.SetOwnerID(clientPool.OwnerID())
	cnr.SetVersion(version.Current())

	CID, err := clientPool.PutContainer(ctx, cnr)
	require.NoError(t, err)
	fmt.Println(CID.String())

	err = clientPool.WaitForContainerPresence(ctx, CID, &pool.ContainerPollingParams{
		CreationTimeout: 30 * time.Second,
		PollInterval:    3 * time.Second,
	})
	require.NoError(t, err)

	return CID
}
