#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= restauth
$(MOD)_SRCS	+= restauth.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
