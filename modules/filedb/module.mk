#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= filedb
$(MOD)_SRCS	+= filedb.c
$(MOD)_LFLAGS	+=

include mk/mod.mk
