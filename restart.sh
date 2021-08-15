#!/bin/bash -xe

sudo systemctl stop envoy
sudo rm /var/log/envoy/access.log
sudo systemctl start envoy

sudo systemctl stop xsuportal-api-golang xsuportal-web-golang

cd ~isucon/repo/webapp/golang
PATH=$PATH:~isucon/local/golang/bin make

sudo systemctl start xsuportal-api-golang xsuportal-web-golang
sudo systemctl status xsuportal-api-golang xsuportal-web-golang

