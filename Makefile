# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
    
all: build
build:
		@GOOS=linux $(GOBUILD) -v -ldflags="-linkmode=external -extldflags=-static" -o "tinydns" cmd/tinydns/tinydns.go
test: 
		$(GOTEST) -v ./...
tidy:
		$(GOMOD) tidy
