.PHONY: build test integration bench
build:
	CGO_ENABLED=1 go build -buildvcs=false -trimpath -o mptcpscan .
test:
	go test -race ./...
	go vet ./...
integration:
	MPTCPSCAN_INTEGRATION=1 go test -race -v ./...
bench:
	go test -run '^$$' -bench . -benchmem
