#!/bin/bash
if [ "$UID" -ne 0 ]; then 
    echo "this script needs to be run in root"
    exit 
fi 
#install, enable, and run docker and deploy a postgres instance 
apt install docker.io 
systemctl enable docker
systemctl start docker 
docker pull postgres
docker run –name <place name here> -e POSTGRES_PASSWORD=<password here> -p 5432:5432 Postgres 
#dbeaver install or just download from their website 
apt install dbeaver

