
#define USB_H_USER_IS_RIOT_INTERNAL

#include <string.h>

#include "usb/usbus.h"
#include "hid_ctap.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"


//todo change
static uint32_t g_cid;

ssize_t usb_hid_stdio_write(const void* buffer, size_t size);

static void send_init_response(uint32_t, uint32_t, uint8_t*);
static void hid_ctap_write(uint8_t cmd, uint32_t cid, void* _data, size_t size);


static uint32_t get_new_cid(void)
{
    static uint32_t cid = 1;

    return cid++;
}

static int is_init_paket(usb_hid_ctap_pkt_t* pkt)
{
    return (pkt->pkt.init.cmd == (USB_HID_CTAP_INIT_PACKET | USB_HID_CTAP_COMMAND_INIT));
}

static int is_broadcast_paket(usb_hid_ctap_pkt_t* pkt)
{
    return (pkt->cid == USB_HID_CTAP_BROADCAST_CID);
}


void hid_ctap_handle_packet(uint8_t* pkt_raw)
{
    usb_hid_ctap_pkt_t *pkt = (usb_hid_ctap_pkt_t*)pkt_raw;

    // To allocate a new channel, the requesting application SHALL use the broadcast channel 
    // CTAPHID_BROADCAST_CID (0xFFFFFFFF)

    DEBUG("CTAP_HID: CID: %04lx \n", pkt->cid);
    DEBUG("CTAP_HID: cmd: %02x \n", pkt->pkt.init.cmd);

    if (is_init_paket(pkt)) {

        if (is_broadcast_paket(pkt)) {
            DEBUG("USB_HID_CTAP: adding new cid \n");

            uint32_t cid_old = pkt->cid;
            uint32_t cid_new = get_new_cid();
            g_cid = cid_new;

            send_init_response(cid_old, cid_new, pkt->pkt.init.payload);
        }
    }
}

static void send_init_response(uint32_t cid_old, uint32_t cid_new, uint8_t* nonce)
{
    DEBUG("USB_HID_CTAP: send_init_response %d\n ", sizeof(usb_hid_ctap_init_resp_t));

    usb_hid_ctap_init_resp_t resp;
    memset(&resp, 0, sizeof(usb_hid_ctap_init_resp_t));

    resp.cid = cid_new;
    memmove(resp.nonce, nonce, 8);
    resp.protocol_version = USB_HID_CTAP_PROTOCOL_VERSION;
    resp.version_major = 0; //?
    resp.version_minor = 0; //?
    resp.build_version = 0; //?

    // USB_HID_CTAP_CAPABILITY_NMSG because no CTAP1 / U2F for now
    resp.capabilities = USB_HID_CTAP_CAPABILITY_CBOR | USB_HID_CTAP_CAPABILITY_WINK | USB_HID_CTAP_CAPABILITY_NMSG;

    hid_ctap_write(USB_HID_CTAP_COMMAND_INIT, cid_old, &resp, sizeof(usb_hid_ctap_init_resp_t));
}

static void hid_ctap_write(uint8_t cmd, uint32_t cid, void* _data, size_t size)
{
    uint8_t * data = (uint8_t *)_data;
    uint8_t buf[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE];
    int offset = 0;
    int bytes_written = 0;
    uint8_t seq = 0;

    if (_data == NULL) {
        memmove(buf, &cid, sizeof(cid));
        offset += sizeof(cid);

        buf[4] = cmd;
        buf[5] = (size & 0xff00) >> 8;
        buf[6] = (size & 0xff) >> 0;
        offset += 3;

        memset(buf + offset, 0, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE - offset);
        usb_hid_stdio_write(buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
        return;
    }

    for (size_t i = 0; i < size; i++) {
        if (offset == 0) {
            memmove(buf, &cid, sizeof(cid));
            offset += sizeof(cid);

            if (bytes_written == 0)
            {
                buf[4] = cmd;
                buf[5] = (size & 0xff00) >> 8;
                buf[6] = (size & 0xff) >> 0;
                offset += 3;
            }
            else
            {
                buf[4] = seq++;
                offset += 1;
            }
        }

        buf[offset++] = data[i];
        bytes_written += 1;

        if (offset == CONFIG_USBUS_HID_INTERRUPT_EP_SIZE) {
            usb_hid_stdio_write(buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
            offset = 0;
        }
    }

    if (offset > 0) {
        memset(buf + offset, 0, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE - offset);
        usb_hid_stdio_write(buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
    }
}
