#!/bin/bash -xe
sudo systemctl stop web-golang.service
cd /home/isucon/webapp/golang
sudo -u isucon PATH=$PATH:/home/isucon/local/golang/bin make
sudo systemctl start web-golang.service
systemctl status web-golang.service
