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
CFLAGS += -DCONFIG_CTAP_TESTING=1

#Disable user presence tests for benchmarking purposes
#CFLAGS += -DCONFIG_CTAP_BENCHMARKS=1

include $(RIOTBASE)/Makefile.include
