#
# srcs.mk All application source files.
#
# Copyright (C) 2010 Creytiv.com
#

SRCS	+= cmd.c
SRCS	+= db.c
SRCS	+= log.c
SRCS	+= main.c
SRCS	+= stun.c
SRCS	+= udp.c
SRCS	+= tcp.c
SRCS	+= dtls.c

ifneq ($(STATIC),)
SRCS	+= static.c
endif
