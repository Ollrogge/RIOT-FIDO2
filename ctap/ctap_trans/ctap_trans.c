#include "ctap.h"
#include "ctap_trans.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#ifdef CONFIG_CTAP_USB
#include "usb/usbus.h"

static uint8_t create_usb(void* report_desc, size_t len);
static int ctap_trans_read_timeout_usb(void* buffer, size_t size, uint32_t timeout);
static usbus_t usbus;
static char usb_stack[USBUS_STACKSIZE];
void usb_hid_io_init(usbus_t* usbus, uint8_t* report_desc, size_t report_desc_size);
ssize_t usb_hid_io_write(const void* buffer, size_t size);
int usb_hid_io_read_timeout(void* buffer, size_t size, uint32_t timeout);
#endif

void ctap_trans_init(void)
{
#ifdef CONFIG_CTAP_USB
    ctap_hid_create();
#endif
}

uint8_t ctap_trans_create(uint8_t type, void* data, size_t len)
{
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            return create_usb((uint8_t*)data, len);
            break;
#endif
        default:
            return CTAP1_ERR_OTHER;
    }
}

int ctap_trans_read_timeout(uint8_t type, void* buffer, size_t len,
                            uint32_t timeout)
{
        switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            return ctap_trans_read_timeout_usb(buffer, len, timeout);
            break;
#endif
        default:
            return -1;
    }
}

int ctap_trans_write(uint8_t type, const void *buffer, size_t len)
{
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            usb_hid_io_write(buffer, len);
            return 0;
            break;
#endif
        default:
            return -1;
    }
}

void ctap_trans_write_keepalive(uint8_t type, uint8_t status)
{
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            ctap_hid_send_keepalive(status);
#endif
        default:
            break;
    }
}

#ifdef CONFIG_CTAP_USB
static uint8_t create_usb(void* report_desc, size_t len)
{
    DEBUG("ctap_trans: creating usb thread \n");
    usbdev_t *usbdev = usbdev_get_ctx(0);
    assert(usbdev);
    usbus_init(&usbus, usbdev);
    usb_hid_io_init(&usbus, (uint8_t*)report_desc, len);

    usbus_create(usb_stack, USBUS_STACKSIZE, USBUS_PRIO, USBUS_TNAME, &usbus);

    return CTAP2_OK;
}

static int ctap_trans_read_timeout_usb(void* buffer, size_t size, uint32_t timeout)
{
    return usb_hid_io_read_timeout(buffer, size, timeout);
}
#endif
