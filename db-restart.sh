#!/bin/bash

sudo systemctl stop mysql
sudo rm /var/log/mysql/slow.log
sudo systemctl start mysql

