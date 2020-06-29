#https://github.com/RIOT-OS/RIOT/blob/master/examples/usbus_minimal/Makefile
APPLICATION=FIDO2

BOARD ?= nrf52840dk

RIOTBASE ?= $(CURDIR)/../RIOT-fork

EXTERNAL_MODULE_DIRS += ./ctap
EXTERNAL_MODULE_DIRS += ./ctaphid

DEVELHELP ?= 1

USEMODULE += usbus
USEMODULE += usbus_hid
USEMODULE += stdio_hid
USEMODULE += xtimer
USEMODULE += isrpipe
USEMODULE += isrpipe_read_timeout
USEMODULE += ctap
USEMODULE += ctaphid

INCLUDES += -I/home1/hops/Uni/BachelorArbeit/RIOT-FIDO2/ctap/include
INCLUDES += -I/home1/hops/Uni/BachelorArbeit/RIOT-FIDO2/ctaphid/include

DISABLE_MODULE += auto_init_usbus

USB_VID = 1915
USB_PID = 521f
PRODUCT_STRING = Nils usb

USEPKG += tinycbor


QUIET ?= 1

include $(RIOTBASE)/Makefile.include

CFLAGS += -DCONFIG_USB_VID=0x$(USB_VID)
CFLAGS += -DCONFIG_USB_PID=0x$(USB_PID)
CFLAGS += -DCONFIG_USB_PRODUCT_STR='"$(PRODUCT_STRING)"'
