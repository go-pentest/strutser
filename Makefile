.DEFAULT_GOAL := all
BINARY=strutser

all: deps build

deps:
	glide install

build:
	go build

clean:
	rm -rf ${BINARY}
	rm -rf vendor
