#!/bin/bash
make clean
go build
./coredns -conf Corefile -dns.port 1053
