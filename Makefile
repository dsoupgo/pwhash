.POSIX:
.PHONY:
.SUFFIXES:

.PHONY: all
all:
	@echo "Nothing to build."

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go mod tidy -diff || (printf '\033[1;31mgo.{mod,sum} out of date. Run "go mod tidy".\033[m\n' && exit 1)
	golangci-lint run
