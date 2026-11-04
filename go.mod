module github.com/KidCarmi/Culvert

go 1.27.0

// The compiler that builds, tests and ships Culvert and its maintenance agent:
// CI (setup-go reads this line), the release binaries and every Docker builder
// stage. It is the ONE source of the version: the Dockerfiles' pinned image
// tags must agree with it and toolchain_consistency_test.go fails any
// disagreement. The `go` line above is the module's minimum language version,
// not the build compiler, and is not raised to match. Upgrade procedure:
// roadmap/CI-REDESIGN.md §20.
toolchain go1.27.3

// GODEBUG pins: compatibility defaults this gateway's posture depends on.
//
// The `go` line above is not only a language minimum — it SELECTS the default
// value of every GODEBUG compatibility setting (`go doc godebug`), so a
// dependency that requires a newer language version silently changes runtime
// security behavior. That is how `x509sslcertoverrideplatform` flipped here:
// sigstore-go v1.4.0 declares `go 1.27.0`, which forced this module's `go` line
// from 1.26.6 to 1.27.0 (PR #1790), and Go 1.27 changed that setting's default
// from 0 to 1. At 1 a `SSL_CERT_FILE`/`SSL_CERT_DIR` in the process environment
// REPLACES the platform certificate verifier on the darwin and windows release
// binaries — displacing the trust anchors `upstreamVerifyRoots` uses to verify
// upstream certificates on SSL-inspected tunnels (proxy_tunnel.go). Pinned to 0
// to keep the platform verifier authoritative there, which is the behavior that
// shipped before that bump and the deterministic, non-environment-displaceable
// one. Linux is unaffected either way: crypto/x509 honors both variables on
// linux at either value.
//
// Every pin here is reviewed and asserted by godebug_pins_test.go, which
// compares this list against the DefaultGODEBUG compiled into the binary. Do
// not add or drop a line without recording why; an unpinned default is one a
// dependency bump can change without review.
godebug x509sslcertoverrideplatform=0

require (
	github.com/KidCarmi/Sluice v0.2.1-0.20260902055746-d6d4394ab74f
	github.com/andybalholm/brotli v1.2.7
	github.com/beevik/etree v1.8.1
	github.com/crewjam/saml v0.5.1
	github.com/dgraph-io/badger/v4 v4.9.6
	github.com/getkin/kin-openapi v0.152.0
	github.com/go-ldap/ldap/v3 v3.4.15
	github.com/goccy/go-yaml v1.19.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.20.3
	github.com/oklog/ulid/v2 v2.1.2
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/playwright-community/playwright-go v0.6000.0
	github.com/sigstore/protobuf-specs v0.5.2
	github.com/sigstore/sigstore-go v1.4.0
	go.etcd.io/etcd/api/v3 v3.7.3
	go.etcd.io/etcd/client/v3 v3.7.3
	go.etcd.io/etcd/server/v3 v3.7.3
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/deckarep/golang-set/v2 v2.8.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20260821105541-05f79448fa77 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-jose/go-jose/v3 v3.0.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v1.0.0 // indirect
	github.com/go-openapi/errors v0.22.9 // indirect
	github.com/go-openapi/jsonpointer v1.0.1 // indirect
	github.com/go-openapi/jsonreference v1.0.2 // indirect
	github.com/go-openapi/loads v0.25.3 // indirect
	github.com/go-openapi/runtime v0.33.3 // indirect
	github.com/go-openapi/runtime/server-middleware v0.33.3 // indirect
	github.com/go-openapi/spec v1.0.1 // indirect
	github.com/go-openapi/strfmt v0.27.4 // indirect
	github.com/go-openapi/swag/conv v0.29.2 // indirect
	github.com/go-openapi/swag/fileutils v0.29.2 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.2 // indirect
	github.com/go-openapi/swag/loading v0.29.2 // indirect
	github.com/go-openapi/swag/mangling v0.29.2 // indirect
	github.com/go-openapi/swag/pools v0.29.2 // indirect
	github.com/go-openapi/swag/stringutils v0.29.2 // indirect
	github.com/go-openapi/swag/typeutils v0.29.2 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.2 // indirect
	github.com/go-openapi/validate v1.0.0 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.4.0 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.22.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.1.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.32.0 // indirect
	github.com/in-toto/attestation v1.2.0 // indirect
	github.com/in-toto/in-toto-golang v0.11.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20211028175153-1c139d1cc84b // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oasdiff/yaml v0.1.1 // indirect
	github.com/oasdiff/yaml3 v0.0.14 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.25.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	github.com/sassoftware/relic/v8 v8.2.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.1 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/rekor v1.5.5 // indirect
	github.com/sigstore/rekor-tiles/v2 v2.4.0 // indirect
	github.com/sigstore/sigstore v1.11.1 // indirect
	github.com/sigstore/timestamp-authority/v2 v2.2.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.4.2 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/transparency-dev/formats v0.1.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.7.3 // indirect
	go.etcd.io/etcd/pkg/v3 v3.7.3 // indirect
	go.etcd.io/raft/v3 v3.7.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261012220534-4341edf3f941 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261005182115-fad411399dd8 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/utils v0.0.0-20260108192941-914a6e750570 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
