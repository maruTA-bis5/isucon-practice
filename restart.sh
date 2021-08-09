#!/bin/bash -xe

#git pull --ff-only

sudo systemctl stop isuumo.go

cd ~/repo/webapp/go
PATH=$PATH:~isucon/local/go/bin make

sudo systemctl start isuumo.go

