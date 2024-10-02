#!/bin/bash
make clean
go build
../coredns/coredns -conf Corefile -dns.port 1053
