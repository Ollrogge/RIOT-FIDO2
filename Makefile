#https://github.com/RIOT-OS/RIOT/blob/master/examples/usbus_minimal/Makefile
APPLICATION=FIDO2

BOARD ?= nrf52840dk

RIOTBASE ?= $(CURDIR)/../RIOT-fork
EXTERNAL_MODULE_DIRS += ./fido

#USEMODULE += shell

DEVELHELP ?= 1

USEMODULE += usbus
#USEMODULE += auto_init_usbus
#USEMODULE += stdio_cdc_acm
#USEMODULE += usbus_cdc_ecm
USEMODULE += usbus_hid
USEMODULE += stdio_hid
USEMODULE += xtimer
USEMODULE += isrpipe
USEMODULE += fido

INCLUDES += -I/home1/hops/Uni/BachelorArbeit/RIOT-FIDO2/fido/include

DISABLE_MODULE += auto_init_usbus

USB_VID = 1915
USB_PID = 521f
PRODUCT_STRING = Nils usb

QUIET ?= 1

include $(RIOTBASE)/Makefile.include

CFLAGS += -DCONFIG_USB_VID=0x$(USB_VID)
CFLAGS += -DCONFIG_USB_PID=0x$(USB_PID)
CFLAGS += -DCONFIG_USB_PRODUCT_STR='"$(PRODUCT_STRING)"'
