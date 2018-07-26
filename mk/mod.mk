#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

$(MOD)_OBJS     := $(patsubst %.c,$(BUILD)/modules/$(MOD)/%.o,$($(MOD)_SRCS))

-include $($(MOD)_OBJS:.o=.d)


$(MOD)_NAME := $(MOD)


ifeq ($(STATIC),)

#
# Dynamically loaded modules
#

$(MOD)$(MOD_SUFFIX): $($(MOD)_OBJS)
	@echo "  LD [M]  $@"
	@$(LD) $(LFLAGS) $(SH_LFLAGS) $(MOD_LFLAGS) $($(basename $@)_OBJS) \
		$($(basename $@)_LFLAGS) -L$(LIBRE_SO) -lre -o $@

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.c $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk
	@echo "  CC [M]  $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)

else

#
# Static linking of modules
#

# needed to deref variable now, append to list
OBJS       := $(OBJS) $($(MOD)_OBJS)
APP_LFLAGS := $(APP_LFLAGS) $($(MOD)_LFLAGS)

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.c $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk
	@echo "  CC [m]  $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -DMOD_NAME=\"$(MOD)\" -c $< -o $@ $(DFLAGS)

endif
