# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

GLAUTH_VERSION ?= v2.4.0
PLUGIN_OS      ?= linux
PLUGIN_ARCH    ?= amd64

.PHONY: plugin glauth-source glauth-bin test docker clean

# Clone glauth at pinned version for shared build (outside vendor/ to avoid Go module conflicts)
GLAUTH_DIR := .glauth-source

glauth-source:
	@if [ ! -d $(GLAUTH_DIR) ]; then \
		git clone --depth 1 --branch $(GLAUTH_VERSION) \
			https://github.com/glauth/glauth $(GLAUTH_DIR); \
	fi

# Build the plugin .so
plugin: glauth-source
	go mod edit -replace github.com/glauth/glauth/v2=./$(GLAUTH_DIR)/v2
	go mod tidy
	CGO_ENABLED=1 GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) \
		go build -buildmode=plugin -o bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/pocketid.so .

plugin_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin

plugin_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugin

plugin_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin

plugin_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin

# Build glauth binary from source (ensures matching toolchain)
glauth-bin: glauth-source
	cd $(GLAUTH_DIR)/v2 && CGO_ENABLED=1 GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) \
		go build -o ../../bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/glauth .

test: glauth-source
	go mod edit -replace github.com/glauth/glauth/v2=./$(GLAUTH_DIR)/v2
	go mod tidy
	go test ./... -v -count=1

docker:
	docker build -f docker/Dockerfile -t glauth-pocketid:latest .

clean:
	rm -rf bin/ $(GLAUTH_DIR)
	git checkout go.mod go.sum 2>/dev/null || true
