FROM golang:1.7-alpine

RUN apk -U add musl-dev gcc make git

RUN mkdir -p /go/src/app
WORKDIR /go/src/app

CMD set -x \
    && go-wrapper download \
    && go build -a -installsuffix cgo -ldflags "-linkmode external -extldflags \"-static\"" -v -o bin/vault-keyscript ./...
