#!/bin/bash -xe

# 本当はmvのほうがいいと思うけど
sudo rm /var/log/mysql/slow.log
sudo systemctl restart mysql.service

sudo systemctl stop web-golang.service
cd /home/isucon/webapp/golang
sudo -u isucon PATH=$PATH:/home/isucon/local/golang/bin make
sudo systemctl start web-golang.service
systemctl status web-golang.service

