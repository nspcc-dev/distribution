module github.com/distribution/distribution/v3

go 1.16

require (
	github.com/Azure/azure-sdk-for-go v56.3.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.20 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.15 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d
	github.com/aws/aws-sdk-go v1.42.27
	github.com/bshuster-repo/logrus-logstash-hook v1.0.0
	github.com/bugsnag/bugsnag-go v0.0.0-20141110184014-b1d153021fcd
	github.com/denverdino/aliyungo v0.0.0-20190125010748-a747050bb1ba
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c
	github.com/docker/go-metrics v0.0.1
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/google/uuid v1.3.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/ncw/swift v1.0.47
	github.com/nspcc-dev/neo-go v0.98.1
	github.com/nspcc-dev/neo-go/examples/nft-nd-nns v0.0.0-20220204081622-62602af34544 // indirect
	github.com/nspcc-dev/neofs-sdk-go v1.0.0-rc.1.0.20220224125909-b5874778e998
	github.com/nspcc-dev/tzhash v1.5.1
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/testcontainers/testcontainers-go v0.12.0
	github.com/yvasiyarov/gorelic v0.0.0-20141212073537-a9bba5b9ab50
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/api v0.20.0
	// when updating google.golang.org/cloud, update (or remove) the replace
	// rule for google.golang.org/grpc accordingly.
	google.golang.org/cloud v0.0.0-20151119220103-975617b05ea8
	google.golang.org/grpc v1.44.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/yaml.v2 v2.4.0
)

// Prevent unwanted updates of grpc. In our codebase, it's a dependency of
// google.golang.org/cloud. However, github.com/spf13/viper (which is an indirect
// dependency of github.com/spf13/cobra) declares a more recent version. Viper
// is not used in the codebase, but go modules uses the go.mod of *all* dependen-
// cies to determine the minimum version of a module, but does *not* check if that
// depdendency's code using the dependency is actually used.
//
// In our case, github.com/spf13/viper occurs as a dependency, but is unused,
// so we can ignore the minimum versions of grpc and jwt-go that it specifies.
//replace google.golang.org/grpc => google.golang.org/grpc v0.0.0-20160317175043-d3ddb4469d5a
