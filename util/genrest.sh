#!/bin/bash
#
# Generate a REST username and password from username, lifetime and shared-secret
#
# Copyright (C) 2010 Creytiv.com
# 
#
# usage:
#
#    genrest.sh <realm> <username> <lifetime> <shared secret>
#


if [ ! $# -eq 4 ]
then
    echo "usage: genrest.sh <realm> <username> <TTL seconds> <shared secret>"
    exit 2
fi

realm=$1
user=$2
ttl=$3
secret=$4
key=$(echo -n "$user:$realm:$secret" | openssl dgst -md5 -binary)

now=$(date +%s)
expire=$(($now + $ttl))
u="$expire:$user"

pass=$(echo -n $u | openssl dgst -binary -sha1 -hmac $key | openssl enc -base64)

echo "username = $u"
echo "password = $pass"
