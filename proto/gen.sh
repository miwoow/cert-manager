#########################################################################
# File Name: gen.sh
# Author: 冷倾殇
# mail: 1500428751@qq.com
# Created Time: Fri 15 Oct 2021 07:51:59 AM EDT
#########################################################################
#!/bin/bash

protoc --proto_path=src --go_out=out --go_opt=paths=source_relative cert_manager.proto
cp ./out/cert_manager.pb.go ../server/src/cert_manager.pb.go
