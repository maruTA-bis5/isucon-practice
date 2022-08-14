#!/bin/bash
sudo apt update
wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.22-1_all.deb
sudo apt -y install ./mysql-apt-config_*_all.deb
sudo apt update
sudo apt install wget gcc g++ make sqlite3 openjdk-17-jdk-headless mysql-client -y
