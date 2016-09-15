#!/bin/bash

docker build --rm -t vault-keyscript:dev .
docker run -it --rm -v $PWD:/go/src/app vault-keyscript:dev
