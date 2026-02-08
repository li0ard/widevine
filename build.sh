#!/bin/bash
protoc --plugin=$(npm root)/.bin/protoc-gen-ts \
 --ts_out=protos \
 -I=protos protos/license_protocol.proto