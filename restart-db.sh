#!/bin/bash -xe

sudo systemctl stop mysql

# rorate log
sudo mv /var/log/mysql/slow.log /var/log/mysql/slow.log.$(date -Iseconds)

sudo systemctl start mysql

