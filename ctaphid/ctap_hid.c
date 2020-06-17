
#define USB_H_USER_IS_RIOT_INTERNAL

#include <string.h>

#include "usb/usbus.h"
#include "ctap_hid.h"
#include "ctap.h"
#include "cbor.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "xtimer.h"
#include "board.h"

//todo: how many concurrent devices should be allowed ?
static ctap_hid_cid_t cids[CTAP_HID_CIDS_MAX];

ssize_t usb_hid_stdio_write(const void* buffer, size_t size);

static void send_init_response(uint32_t, uint32_t, uint8_t*);
static void ctap_hid_write(uint8_t cmd, uint32_t cid, void* _data, size_t size);

static void handle_init_packet(ctap_hid_pkt_t *pkt);
static void handle_cbor_packet(ctap_hid_pkt_t *pkt);

static void wink(ctap_hid_pkt_t *pkt);
static void send_init_response(uint32_t cid_old, uint32_t cid_new, uint8_t* nonce);

static int8_t add_cid(uint32_t cid);
static uint32_t get_new_cid(void);
static uint16_t get_packet_len(ctap_hid_pkt_t* pkt);


static uint32_t get_new_cid(void)
{
    //channel id 0 is reserved
    static uint32_t cid = 1;

    return cid++;
}

static int8_t add_cid(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (!cids[i].taken) {
            cids[i].taken = 1;
            cids[i].cid = cid;

            return 0;
        }
    }
    return -1;
}

static uint16_t get_packet_len(ctap_hid_pkt_t* pkt)
{
    return (uint16_t)((pkt->init.bcnth << 8) | pkt->init.bcntl);
}

static int8_t cid_exists(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            return 0;
        }
    }
    return -1;
}

/*
static int8_t delete_cid(uint32_t cid)
{
    for (int i = 0; i < USB_HID_CTAP_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            cids[i].taken = 0;
            cids[i].cid = 0;

            return 0;
        }
    }

    return -1;
}
*/

void ctap_hid_handle_packet(uint8_t* pkt_raw)
{
    ctap_hid_pkt_t *pkt = (ctap_hid_pkt_t*)pkt_raw;

    DEBUG("CTAP_HID: CID: %04lx \n", pkt->cid);
    DEBUG("CTAP_HID: cmd: %02x \n", pkt->init.cmd);

    uint8_t cmd = pkt->init.cmd;

    switch(cmd) {
        case CTAP_HID_COMMAND_INIT:
            handle_init_packet(pkt);
            break;
        case CTAP_HID_COMMAND_CBOR:
            //todo: CBOR msg = FIDO specific messages
            DEBUG("CTAP_HID: CBOR COMMAND \n");
            handle_cbor_packet(pkt);
            break;
        case CTAP_HID_COMMAND_WINK:
            DEBUG("CTAP_HID: wink \n");
            wink(pkt);
            break;
        case CTAP_HID_COMMAND_PING:
            DEBUG("CTAP_HID: ping %d \n", get_packet_len(pkt));
            ctap_hid_write(pkt->init.cmd, pkt->cid, pkt->init.payload, get_packet_len(pkt));
            break;
        case CTAP_HID_COMMAND_CANCEL:
            DEBUG("CTAP_HID: cancel \n");
            break;
        default:
            DEBUG("Ctaphid: unknown command \n");
    }
}

static void wink(ctap_hid_pkt_t *pkt)
{
    uint32_t delay = 400000;
    //led3 before led2 due to led layout on nRF52840DK
    for (int i = 1; i <= 8; i++) {
#ifdef LED0_TOGGLE
        LED0_TOGGLE;
        xtimer_usleep(delay);
#endif
#ifdef LED1_TOGGLE
        LED1_TOGGLE;
        xtimer_usleep(delay);
#endif
#ifdef LED3_TOGGLE
        LED3_TOGGLE;
        xtimer_usleep(delay);
#endif
#ifdef LED2_TOGGLE
        LED2_TOGGLE;
        xtimer_usleep(delay);
#endif
        delay /= 2;
    }

    ctap_hid_write(pkt->init.cmd, pkt->cid, NULL, 0);
}

/* CTAP specification (version 20190130) section 8.1.9.1.3 */
static void handle_init_packet(ctap_hid_pkt_t *pkt)
{
    uint8_t cmd;
    uint32_t cid;
    uint32_t cid_new;

    /* cid 0 is reserved */
    if (pkt->cid == 0) {
        uint8_t err = CTAP_HID_ERROR_INVALID_CHANNEL;
        cmd = CTAP_HID_COMMAND_ERROR;;
        cid = pkt->cid;
        ctap_hid_write(cmd, cid, &err, sizeof(err));
    }
    /* check for len described in standard */
    else if (get_packet_len(pkt) != 8)
    {
        uint8_t err = CTAP_HID_ERROR_INVALID_LEN;
        cmd = CTAP_HID_COMMAND_ERROR;
        cid = pkt->cid;
        ctap_hid_write(cmd, cid, &err, sizeof(err));
    }
    /* create new channel */
    else if (pkt->cid == CTAP_HID_BROADCAST_CID) {
        cid_new = get_new_cid();
        cid = pkt->cid;
        if (add_cid(cid_new) == -1) {
            uint8_t err = CTAP_HID_ERROR_CHANNEL_BUSY;
            cmd = CTAP_HID_COMMAND_ERROR;
            ctap_hid_write(cmd, cid, &err, sizeof(err));
            return;
        }

        send_init_response(cid, cid_new, pkt->init.payload);
    }
    /* synchronize channel */
    else {
        cid = pkt->cid;
        if (cid_exists(cid) == -1) {
            if (add_cid(cid) == -1) {
                uint8_t err = CTAP_HID_ERROR_CHANNEL_BUSY;
                cmd = CTAP_HID_COMMAND_ERROR;
                ctap_hid_write(cmd, cid, &err, sizeof(err));
                return;
            }
        }
        send_init_response(cid, cid, pkt->init.payload);
    }
}

/* CTAP specification (version 20190130) section 8.1.9.1.2 */
static void handle_cbor_packet(ctap_hid_pkt_t *pkt)
{
    uint8_t cmd;
    uint32_t cid;
    ctap_resp_t resp;
    uint8_t err;
    size_t size;

    if (get_packet_len(pkt) == 0) {
        err = CTAP_HID_ERROR_INVALID_LEN;
        cmd = CTAP_HID_COMMAND_ERROR;
        cid = pkt->cid;
        ctap_hid_write(cmd, cid, &err, sizeof(err));
        return;
    }

    memset(&resp, 0, sizeof(ctap_resp_t));

    size = ctap_handle_request(pkt->init.payload, &resp);
    cmd = pkt->init.cmd;
    cid = pkt->cid;

    DEBUG("cbor answer size: %u \n", size);

    if (resp.status == CTAP2_OK) {
        ctap_hid_write(cmd, cid, &resp, size + sizeof(uint8_t));
    }
    else {
        ctap_hid_write(cmd, cid, &resp.status, sizeof(uint8_t));
    }
}

static void send_init_response(uint32_t cid_old, uint32_t cid_new, uint8_t* nonce)
{
    DEBUG("USB_HID_CTAP: send_init_response %d\n ", sizeof(ctap_hid_init_resp_t));

    ctap_hid_init_resp_t resp;
    memset(&resp, 0, sizeof(ctap_hid_init_resp_t));

    resp.cid = cid_new;
    memmove(resp.nonce, nonce, 8);
    resp.protocol_version = CTAP_HID_PROTOCOL_VERSION;
    resp.version_major = 0; //?
    resp.version_minor = 0; //?
    resp.build_version = 0; //?

    uint8_t cmd = (CTAP_HID_INIT_PACKET | CTAP_HID_COMMAND_INIT);

    // USB_HID_CTAP_CAPABILITY_NMSG because no CTAP1 / U2F for now
    resp.capabilities = CTAP_HID_CAPABILITY_CBOR | CTAP_HID_CAPABILITY_WINK | CTAP_HID_CAPABILITY_NMSG;
    //resp.capabilities = CTAP_HID_CAPABILITY_WINK | CTAP_HID_CAPABILITY_NMSG;

    ctap_hid_write(cmd, cid_old, &resp, sizeof(ctap_hid_init_resp_t));
}

static void ctap_hid_write(uint8_t cmd, uint32_t cid, void* _data, size_t size)
{
    uint8_t * data = (uint8_t *)_data;
    uint8_t buf[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE];
    int offset = 0;
    int bytes_written = 0;
    uint8_t seq = 0;

    memmove(buf, &cid, sizeof(cid));
    offset += sizeof(cid);
    buf[4] = cmd;
    buf[5] = (size & 0xff00) >> 8;
    buf[6] = (size & 0xff) >> 0;
    offset += 3;

    if (_data == NULL) {
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
