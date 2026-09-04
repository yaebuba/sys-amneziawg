#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

ifeq ($(strip $(DEVKITPRO)),)
$(error "Set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

#---------------------------------------------------------------------------------
TARGET      := sys-amneziawg
BUILD       := build
SOURCES     := source source/crypto source/lwip_port \
               source/lwip/core source/lwip/core/ipv4
DATA        := data
INCLUDES    := source source/crypto source/lwip_port source/lwip/include
CONFIG_JSON := sys-amneziawg.json

#---------------------------------------------------------------------------------
ARCH    := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE

CFLAGS  := -g -Wall -Wextra -O2 -ffunction-sections \
           $(ARCH) $(DEFINES) \
           -D__SWITCH__ -DSWITCH_SYSMODULE

CFLAGS  += $(INCLUDE)

CXXFLAGS := $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++17

ASFLAGS := -g $(ARCH)
LDFLAGS  = -specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) \
           -Wl,-Map,$(notdir $*.map)

LIBS    := -lnx

LIBDIRS := $(PORTLIBS) $(LIBNX)

#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT   := $(CURDIR)/$(TARGET)
export TOPDIR   := $(CURDIR)
export VPATH    := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
                   $(foreach dir,$(DATA),$(CURDIR)/$(dir))
export DEPSDIR  := $(CURDIR)/$(BUILD)

CFILES   := awg_obf.c awg_config.c awg_rand.c awg_noise.c awg_ipprobe.c awg_session.c awg_power.c \
            awg_netif.c main_switch.c \
            blake2s.c chacha20.c chacha20poly1305.c poly1305-donna.c x25519.c crypto.c \
            sys_arch.c \
            init.c def.c mem.c memp.c netif.c pbuf.c ip.c inet_chksum.c \
            tcp.c tcp_in.c tcp_out.c udp.c raw.c timeouts.c sys.c stats.c \
            dns.c awg_proxy.c \
            ip4.c ip4_addr.c ip4_frag.c icmp.c
CPPFILES :=
SFILES   :=

export LD := $(CC)

export OFILES_SRC := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES     := $(OFILES_SRC)
export HFILES_BIN :=

export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                  $(foreach dir,$(LIBDIRS),-I$(dir)/include) \
                  -I$(CURDIR)/$(BUILD)

export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

ifeq ($(strip $(CONFIG_JSON)),)
	jsons := $(wildcard *.json)
	ifneq (,$(findstring $(TARGET).json,$(jsons)))
		export APP_JSON := $(TOPDIR)/$(TARGET).json
	endif
else
	export APP_JSON := $(TOPDIR)/$(CONFIG_JSON)
endif

.PHONY: $(BUILD) clean all

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET).nsp $(TARGET).nso $(TARGET).npdm $(TARGET).elf out

#---------------------------------------------------------------------------------
else
.PHONY: all

DEPENDS := $(OFILES:.o=.d)

all: $(OUTPUT).nsp

$(OUTPUT).nsp : $(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso : $(OUTPUT).elf
$(OUTPUT).elf : $(OFILES)

-include $(DEPENDS)

endif
