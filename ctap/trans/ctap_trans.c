#include "event.h"

#include "ctap.h"
#include "ctap_trans.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#ifdef CONFIG_CTAP_USB
static ctap_trans_io_t g_ctap_trans_hid_io;
static ctap_trans_io_t g_usb_io;
static uint8_t create_usb(void* report_desc, size_t len);
static void ctap_trans_write_usb(const void *buffer, size_t len);
static int ctap_trans_read_timeout_usb(void* buffer, size_t size,
                                        uint32_t timeout);

static void data_hid_in_cb(usbus_hid_device_t *hid, uint8_t *data, size_t len);
static void data_usb_in_cb(uint8_t *data, size_t len);
static void data_usb_out_cb(uint8_t *data, size_t len);
#ifdef CONFIG_CTAP_NATIVE
#include "ctap_udp.h"
#else
#include "usb/usbus.h"
static char usb_stack[USBUS_STACKSIZE];
static usbus_t usbus;
ssize_t usb_hid_io_write(const void* buffer, size_t size);
int usb_hid_io_read_timeout(void* buffer, size_t size, uint32_t timeout);
void usb_hid_io_init(usbus_t *usbus, uint8_t *report_desc,
                    size_t report_desc_size);
#endif
#endif

static mutex_t g_ctap_data_mut;
static ctap_trans_data_t g_ctap_data;


static void ctap_loop(void)
{
    while (1) {
        event_wait_timeout(&queue, )
    }
}


static void handler(event *event)
{

}

static event_t ev = { .handler = handler };
static event_queue_t queue;



static void ctap_trans_cb(uint8_t type, uint8_t* req, size_t size,
                         bool (*should_cancel)(void))
{
    mutex_lock(&g_ctap_data_mut);
    memset(g_ctap_data);
    assert(size <= sizeof(g_ctap_data.req_buf));
    memmove(g_ctap_data.req_buf, req, size);
    g_ctap_data.size = size;
    g_ctap_data.should_cancel = should_cancel;
    g_ctap_data.trans_type = type;

    event_post(&queue, &ev);
}

void ctap_trans_init(void)
{
    mutex_init(&g_ctap_data_mut);
    event_queue_init(&queue);
#ifdef CONFIG_CTAP_USB
    g_usb_io.out = data_usb_out_cb;

    ctap_trans_hid_create(g_usb_io.out);
#endif
}

uint8_t ctap_trans_create(uint8_t type, void* data, size_t len, ctap_trans_cb_t cb)
{
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            return create_usb((uint8_t*)data, len, cb);
            break;
#endif
        default:
            return CTAP1_ERR_OTHER;
    }
}

int ctap_trans_read_timeout(uint8_t type, void* buffer, size_t len,
                            uint32_t timeout)
{
    (void)buffer;
    (void)len;
    (void)timeout;
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
    (void)buffer;
    (void)len;
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            ctap_trans_write_usb(buffer, len);
            return 0;
            break;
#endif
        default:
            return -1;
    }
}

void ctap_trans_write_keepalive(uint8_t type, uint8_t status)
{
    (void)status;
    switch (type) {
#ifdef CONFIG_CTAP_USB
        case CTAP_TRANS_USB:
            ctap_trans_hid_send_keepalive(status);
#endif
        default:
            break;
    }
}

#ifdef CONFIG_CTAP_USB
static uint8_t create_usb(void* report_desc, size_t len, ctap_trans_cb_t cb)
{
    g_usb_io.in = cb;
#ifdef CONFIG_CTAP_NATIVE
    (void)report_desc;
    (void)len;
    ctap_udp_create(g_usb_io.in);
#else
    usbdev_t *usbdev = usbdev_get_ctx(0);
    assert(usbdev);
    usbus_init(&usbus, usbdev);
    usb_hid_io_init_cb(&usbus, report_desc, len, data_hid_in_cb);
    usbus_create(usb_stack, USBUS_STACKSIZE, USBUS_PRIO, USBUS_TNAME, &usbus);
#endif
    return CTAP2_OK;
}

static void data_hid_in_cb(usbus_hid_device_t *hid, uint8_t *data, size_t len)
{
    (void)hid;
    g_usb_io.in(data, len);
}

static void data_usb_out_cb(uint8_t *buffer, size_t len)
{
#ifdef CONFIG_CTAP_NATIVE
    ctap_udp_write(buffer, len);
#else
    usb_hid_io_write(buffer, len);
#endif
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
#endif
