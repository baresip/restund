#!/bin/sh
#
# Generate a HA1 from username, realm and password
#
# HA1 = MD5(username:realm:password)
#
# usage:
#
#    genha1.sh username realm password
#

username=$1
realm=$2
password=$3

if [ ! $# -eq 3 ]
then
    echo "usage: genha1.sh <username> <realm> <password>"
    exit 2
fi

ha1=$(echo -n "$username:$realm:$password" | md5sum | tr -cd "[0-9a-f]")
echo "$username:$ha1"
