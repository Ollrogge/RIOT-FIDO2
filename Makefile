APPLICATION=FIDO2

ifeq ($(native), 1)
    CFLAGS += -DCONFIG_CTAP_NATIVE=1
    BOARD ?= native
else
    BOARD ?= nrf52840dk
endif

RIOTBASE ?= $(CURDIR)/RIOT

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEMODULE += ctap
EXTERNAL_MODULE_DIRS += $(CURDIR)/ctap
INCLUDES += -I$(CURDIR)/ctap/include

DEVELHELP ?= 1
QUIET ?= 1

USB_VID ?= ${USB_VID_TESTING}
USB_PID ?= ${USB_PID_TESTING}


#Enable authenticatorReset method
#CFLAGS += -DCONFIG_CTAP_TESTING=1

#Disable user presence tests for benchmarking purposes
#CFLAGS += -DCONFIG_CTAP_BENCHMARKS=1

#todo: where to put presets ?
DEVICE_AAGUID_TESTING="0x9c, 0x29, 0x58, 0x65, 0xfa, 0x2c, 0x36, 0xb7, \
                      0x05, 0xa4, 0x23, 0x20, 0xaf, 0x9c, 0x8f, 0x16"

#AAGUID has to be 128 bits
CFLAGS += -DCONFIG_CTAP_AAGUID=${DEVICE_AAGUID_TESTING}

include $(RIOTBASE)/Makefile.include