# Restund

restund - modular STUN/TURN server

- Copyright (c) 2010 - 2020 Creytiv.com
- Copyright (C) 2020 - 2023 Baresip Foundation (https://github.com/baresip)

Distributed under BSD-3-Clause license

## Design goals:

* Modular STUN/TURN server
* STUN and TURN support
* IPv4 and IPv6 support
* UDP, TCP, TLS and DTLS transport support
* RFC-compliancy
* Robust, fast, low footprint
* Portable C89 and C99 source code

## Modular Plugin Architecture:

* STUN messages:    auth binding stat turn
* Database backend: mysql_ser filedb restauth
* Server status:    status
* Logging:          syslog

## IETF RFCs:

* RFC 5389 - Session Traversal Utilities for NAT (STUN)
* RFC 5766 - Traversal Using Relays around NAT (TURN): Relay Extensions to
             Session Traversal Utilities for NAT (STUN)
* RFC 5780 - NAT Behavior Discovery Using Session Traversal Utilities for
             NAT (STUN)
* RFC 6156 - Traversal Using Relays around NAT (TURN) Extension for IPv6
* RFC 7350 - DTLS as Transport for STUN
* draft-uberti-behave-turn-rest-00

## Building

```bash
git clone https://github.com/baresip/re
cd re && cmake -B build && cmake --build build -j
cd ..

git clone https://github.com/baresip/restund
cd restund && cmake -B build && cmake --build build -j
```

See [docs](docs) for more information.
