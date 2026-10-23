# Crivo: build, testes e ícone do Windows.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X crivo/internal/cli.Version=$(VERSION)
# Windows: estático, sem depender do libwinpthread-1.dll do MinGW
ifeq ($(OS),Windows_NT)
LDFLAGS += -extldflags=-static
endif

.PHONY: build test test-integration fuzz winres vet clean tag

build:
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/crivo ./cmd/crivo

test:
	go test ./...

# Postgres real: CRIVO_TEST_DSN=postgres://usuario:senha@host:5432/banco make test-integration
# (sem a variável, usa testcontainers-go se houver Docker)
test-integration:
	go test -v ./internal/integration/

fuzz:
	go test -run XXX -fuzz FuzzGuard -fuzztime 60s ./internal/sqlguard/

vet:
	go vet ./...

# Regenera os .syso do ícone (cmd/crivo/winres/winres.json). Os binários
# gerados pelo crivo build são cópias do crivo.exe e herdam o ícone.
winres:
	go install github.com/tc-hib/go-winres@latest
	cd cmd/crivo && go-winres make --arch amd64,arm64

clean:
	rm -rf bin dist

# Cria a tag anotada e publica: o CI (job release) gera o GitHub Release com
# os binários de Linux, macOS (arm64 e Intel) e Windows.
#   make tag TAG=v0.2.0
tag:
	@case "$(TAG)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "uso: make tag TAG=vX.Y.Z"; exit 1;; esac
	@test -z "$$(git status --porcelain)" || { echo "árvore suja: commite antes de taguear"; exit 1; }
	git tag -a "$(TAG)" -m "$(TAG)"
	git push origin main "$(TAG)"
