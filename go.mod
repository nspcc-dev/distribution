module github.com/distribution/distribution/v3

go 1.18

require (
	github.com/Azure/azure-sdk-for-go v56.3.0+incompatible
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d
	github.com/aws/aws-sdk-go v1.43.16
	github.com/bshuster-repo/logrus-logstash-hook v1.0.0
	github.com/bugsnag/bugsnag-go v0.0.0-20141110184014-b1d153021fcd
	github.com/denverdino/aliyungo v0.0.0-20190125010748-a747050bb1ba
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c
	github.com/docker/go-metrics v0.0.1
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/ncw/swift v1.0.47
	github.com/nspcc-dev/neo-go v0.98.1
	github.com/nspcc-dev/neo-go/examples/nft-nd-nns v0.0.0-20220204081622-62602af34544 // indirect
	github.com/nspcc-dev/neofs-sdk-go v0.0.0-20220201141054-6a7ba33b59ef
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/prometheus/client_golang v1.12.1 // indirect; updated to latest
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/yvasiyarov/gorelic v0.0.0-20141212073537-a9bba5b9ab50
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c
	google.golang.org/api v0.30.0
	google.golang.org/cloud v0.0.0-20151119220103-975617b05ea8
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/yaml.v2 v2.4.0
)

require (
	cloud.google.com/go v0.65.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.24 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.18 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/bugsnag/osext v0.0.0-20130617224835-0dd3f918b21b // indirect
	github.com/bugsnag/panicwrap v0.0.0-20151223152923-e2c28503fcd0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/osext v0.0.0-20151018003038-5e2d6d41470f // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/nspcc-dev/go-ordered-json v0.0.0-20220111165707-25110be27d22 // indirect
	github.com/nspcc-dev/hrw v1.0.9 // indirect
	github.com/nspcc-dev/neo-go/pkg/interop v0.0.0-20220131192108-37ca96c20bf7 // indirect
	github.com/nspcc-dev/neofs-api-go/v2 v2.11.2-0.20220127135316-32dd0bb3f9c5 // indirect
	github.com/nspcc-dev/neofs-crypto v0.3.0 // indirect
	github.com/nspcc-dev/rfc6979 v0.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rogpeppe/go-internal v1.6.1 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/pflag v1.0.3 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20210305035536-64b5b1c73954 // indirect
	github.com/urfave/cli v1.22.5 // indirect
	github.com/yvasiyarov/go-metrics v0.0.0-20140926110328-57bccd1ccd43 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20140908184405-b21fdbd4370f // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.opencensus.io v0.22.4 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.18.1 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/genproto v0.0.0-20200825200019-8632dd797987 // indirect
	google.golang.org/grpc v1.41.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
