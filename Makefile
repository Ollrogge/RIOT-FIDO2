#https://github.com/RIOT-OS/RIOT/blob/master/examples/usbus_minimal/Makefile
APPLICATION=FIDO2

BOARD ?= nrf52840dk

RIOTBASE ?= $(CURDIR)/RIOT

EXTERNAL_MODULE_DIRS += ./ctap
EXTERNAL_MODULE_DIRS += ./ctaphid

DEVELHELP ?= 1

FEATURES_REQUIRED += periph_flashpage

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEMODULE += usbus_hid
USEMODULE += ctaphid
USEMODULE += ctap
USEMODULE += hashes
USEMODULE += fmt
USEMODULE += periph_gpio_irq
USEMODULE += crypto_aes
USEMODULE += cipher_modes

INCLUDES += -I$(CURDIR)/ctap/include
INCLUDES += -I$(CURDIR)/ctaphid/include

DISABLE_MODULE += auto_init_usbus

USB_VID = 1915
USB_PID = 521f
PRODUCT_STRING = Nils usb

USEPKG += tinycbor
USEPKG += relic

QUIET ?= 1

include $(RIOTBASE)/Makefile.include

# The rest of the parameters are configuration parameters for RELIC described in its documentation.
export RELIC_CONFIG_FLAGS=-DARCH=NONE -DOPSYS=NONE -DQUIET=off -DWORD=32 -DFP_PRIME=256 -DWITH="BN;MD;DV;FP;EP;CP;BC;EC" -DSEED=RIOTRND

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