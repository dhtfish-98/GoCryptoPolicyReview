.PHONY: test vet build

test:
	GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 go test -count=1 ./...

vet:
	GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 go vet ./...

build:
	GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-buildid= -o dist/gocrypto-policy-review ./cmd/gocrypto-policy-review
