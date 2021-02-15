#include "ctap.h"
#include "ctap_trans.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static uint8_t create_usb(const void* report_desc, size_t len);
static void ctap_trans_write_usb(const void *buffer, size_t len);
static int ctap_trans_read_timeout_usb(void* buffer, size_t size,
                                        uint32_t timeout);
#ifdef CONFIG_CTAP_NATIVE
#include "ctap_udp.h"
#else
#include "usb/usbus.h"
static char usb_stack[USBUS_STACKSIZE];
static usbus_t usbus;
size_t usb_hid_io_write(const void* buffer, size_t size);
int usb_hid_io_read_timeout(void* buffer, size_t size, uint32_t timeout);
void usb_hid_io_init(usbus_t *usbus, const uint8_t *report_desc,
                    size_t report_desc_size);
#endif

static char g_stack[16384];
static void* pkt_loop(void* arg);
static kernel_pid_t g_pid;

static void* pkt_loop(void* arg)
{
    (void) arg;
    ctap_init();

    uint8_t buffer[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE];
    int read;
    while (1) {
        read = ctap_trans_read_timeout_usb(buffer,
        CONFIG_USBUS_HID_INTERRUPT_EP_SIZE, CTAP_HID_TRANSACTION_TIMEOUT);

        if (read == CONFIG_USBUS_HID_INTERRUPT_EP_SIZE) {
            ctap_trans_hid_handle_packet(buffer);
        }

        ctap_trans_hid_check_timeouts();
    }

    return (void*)0;
}

void ctap_trans_init(void)
{
    g_pid = thread_create(g_stack, sizeof(g_stack), THREAD_PRIORITY_MAIN, THREAD_CREATE_STACKTEST,
                          pkt_loop, NULL, "ctap_trans_loop");
    DEBUG("ctap_trans pkt loop created \n");

    ctap_trans_hid_create();
}

uint8_t ctap_trans_create(uint8_t type, const void* report_desc, size_t len)
{
    switch (type) {
        case CTAP_TRANS_USB:
            return create_usb(report_desc, len);
            break;
        default:
            return CTAP1_ERR_OTHER;
    }
}

int ctap_trans_read_timeout(uint8_t type, void* buffer, size_t len,
                            uint32_t timeout)
{
    switch (type) {
        case CTAP_TRANS_USB:
            return ctap_trans_read_timeout_usb(buffer, len, timeout);
            break;
        default:
            return -1;
    }
}

int ctap_trans_write(uint8_t type, const void *buffer, size_t len)
{
    switch (type) {
        case CTAP_TRANS_USB:
            ctap_trans_write_usb(buffer, len);
            return 0;
            break;
        default:
            return -1;
    }
}

void ctap_trans_write_keepalive(uint8_t type, uint8_t status)
{
    switch (type) {
        case CTAP_TRANS_USB:
            ctap_trans_hid_send_keepalive(status);
        default:
            break;
    }
}

static uint8_t create_usb(const void* report_desc, size_t len)
{
#ifdef CONFIG_CTAP_NATIVE
   (void)report_desc;
   (void)len;
   ctap_udp_create();
#else
    usbdev_t *usbdev = usbdev_get_ctx(0);
    assert(usbdev);
    usbus_init(&usbus, usbdev);
    usb_hid_io_init(&usbus, report_desc, len);

    usbus_create(usb_stack, USBUS_STACKSIZE, USBUS_PRIO, USBUS_TNAME, &usbus);
#endif
    return CTAP2_OK;
}

static int ctap_trans_read_timeout_usb(void* buffer, size_t size, uint32_t timeout)
{
#ifdef CONFIG_CTAP_NATIVE
    return ctap_udp_read_timeout(buffer, size, timeout);
#else
    return usb_hid_io_read_timeout(buffer, size, timeout);
#endif
}

static void ctap_trans_write_usb(const void *buffer, size_t len)
{
#ifdef CONFIG_CTAP_NATIVE
    ctap_udp_write(buffer, len);
#else
    usb_hid_io_write(buffer, len);
#endif
}
