#!/bin/bash
protoc --plugin=$(npm root)/.bin/protoc-gen-ts \
 --ts_out=src/protos \
 -I=src/protos src/protos/license_protocol.proto