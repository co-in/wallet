module github.com/co-in/wallet

go 1.25

replace (
	github.com/co-in/storage => ../storage
	github.com/co-in/storage/badger => ../storage/badger
	github.com/co-in/storage/bbolt => ../storage/bbolt
	github.com/co-in/storage/tests => ../storage/tests
)

require (
	github.com/co-in/prkg v1.0.0
	github.com/co-in/storage v0.0.0-20251227173256-b58a9e9909f4
	github.com/co-in/storage/badger v0.0.0-00010101000000-000000000000
	github.com/dgraph-io/badger/v4 v4.9.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
