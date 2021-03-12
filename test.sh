#!/usr/bin/env bash
set -x
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e 127.0.0.1 || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e 127.0.0.2 || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e 255.255.255.255 || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e 169.254.0.1 || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e 0.0.0.0 || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e "::1" || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e "::" || exit 1
! turnutils_uclient  127.0.0.1 -X -u demo -w secret -e "fe80::" || exit 1


