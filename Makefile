#https://github.com/RIOT-OS/RIOT/blob/master/examples/usbus_minimal/Makefile
APPLICATION=FIDO2

ifeq ($(native), 1)
    CFLAGS += -DCONFIG_CTAP_NATIVE=1
    BOARD ?= native
else
    BOARD ?= nrf52840dk
endif


RIOTBASE ?= $(CURDIR)/RIOT

EXTERNAL_MODULE_DIRS += $(CURDIR)/ctap

DEVELHELP ?= 1

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEMODULE += ctap

INCLUDES += -I$(CURDIR)/ctap/include

USB_VID = 1915
USB_PID = 521f
PRODUCT_STRING = Nils usb

QUIET ?= 1

CFLAGS += -DCONFIG_USB_VID=0x$(USB_VID)
CFLAGS += -DCONFIG_USB_PID=0x$(USB_PID)
CFLAGS += -DCONFIG_USB_PRODUCT_STR='"$(PRODUCT_STRING)"'

CFLAGS += -DCONFIG_CTAP_OPTIONS_RK=1

CFLAGS += -DCONFIG_CTAP_TESTING=1
CFLAGS += -DCONFIG_CTAP_BENCHMARKS=1

#todo: where to put presets ?
DEVICE_AAGUID_TESTING="0x9c, 0x29, 0x58, 0x65, 0xfa, 0x2c, 0x36, 0xb7, \
                      0x05, 0xa4, 0x23, 0x20, 0xaf, 0x9c, 0x8f, 0x16"

#AAGUID has to be 128 bits
CFLAGS += -DCONFIG_CTAP_AAGUID=${DEVICE_AAGUID_TESTING}

include $(RIOTBASE)/Makefile.include