#define USB_H_USER_IS_RIOT_INTERNAL

#include <string.h>

#include "usb/usbus.h"
#include "ctap_hid.h"
#include "ctap.h"
#include "cbor.h"

#include "thread.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "xtimer.h"
#include "board.h"

#include "mutex.h"

//todo: how many concurrent devices should be allowed ?
static ctap_hid_cid_t cids[CTAP_HID_CIDS_MAX];

static uint8_t is_init_pkt(ctap_hid_pkt_t* pkt);

static ctap_hid_buffer_t ctap_hid_buffer;

static kernel_pid_t worker_pid;
static char worker_stack[8192];
static void* pkt_worker(void* pkt_raw);

ssize_t usb_hid_stdio_write(const void* buffer, size_t size);

static void send_init_response(uint32_t, uint32_t, uint8_t*);
static void send_error_response(uint32_t cid, uint8_t err);
static void ctap_hid_write(uint8_t cmd, uint32_t cid, void* _data, size_t size);

static uint32_t handle_init_packet(uint32_t cid, uint16_t bcnt, uint8_t* payload);
static void handle_cbor_packet(uint32_t cid, uint16_t bcnt, uint8_t cmd, uint8_t* payload);
static void wink(uint32_t cid, uint8_t cmd);
static void send_init_response(uint32_t cid_old, uint32_t cid_new, uint8_t* nonce);

static int8_t add_cid(uint32_t cid);
static uint8_t cid_exists(uint32_t cid);
static uint32_t get_new_cid(void);
static uint16_t get_packet_len(ctap_hid_pkt_t* pkt);

static mutex_t is_busy_mutex;
static uint8_t is_busy = 0;

static uint8_t is_init_pkt(ctap_hid_pkt_t* pkt)
{
    return ((pkt->init.cmd & CTAP_HID_INIT_PACKET) == CTAP_HID_INIT_PACKET);
}

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

static int8_t delete_cid(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            cids[i].taken = 0;
            cids[i].cid = 0;

            return 0;
        }
    }
    return -1;
}

static uint8_t cid_exists(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            return 1;
        }
    }
    return 0;
}

static uint16_t get_packet_len(ctap_hid_pkt_t* pkt)
{
    return (uint16_t)((pkt->init.bcnth << 8) | pkt->init.bcntl);
}

static uint8_t buffer_pkt(ctap_hid_pkt_t *pkt)
{
    if (is_init_pkt(pkt)) {
        ctap_hid_buffer.bcnt = get_packet_len(pkt);
        uint16_t size = (ctap_hid_buffer.bcnt < CTAP_HID_INIT_PAYLOAD_SIZE) ?
                        ctap_hid_buffer.bcnt : CTAP_HID_INIT_PAYLOAD_SIZE;
        ctap_hid_buffer.cmd = pkt->init.cmd;
        ctap_hid_buffer.cid = pkt->cid;
        ctap_hid_buffer.seq = -1;
        memmove(ctap_hid_buffer.buffer, pkt->init.payload, size);
        ctap_hid_buffer.offset = size;
    }
    else {
        int left = ctap_hid_buffer.bcnt - ctap_hid_buffer.offset;
        int diff = left - CTAP_HID_CONT_PAYLOAD_SIZE;
        ctap_hid_buffer.seq += 1;

        if (pkt->cont.seq != ctap_hid_buffer.seq) {
            ctap_hid_buffer.err = CTAP_HID_ERROR_INVALID_SEQ;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        if (diff <= 0) {
            memmove(ctap_hid_buffer.buffer, pkt->cont.payload, left);
            ctap_hid_buffer.offset += left;
        }
        else {
            memmove(ctap_hid_buffer.buffer, pkt->cont.payload, CTAP_HID_CONT_PAYLOAD_SIZE);
            ctap_hid_buffer.offset += CTAP_HID_CONT_PAYLOAD_SIZE;
        }
    }

    return ctap_hid_buffer.offset == ctap_hid_buffer.bcnt ?
           CTAP_HID_BUFFER_STATUS_DONE : CTAP_HID_BUFFER_STATUS_BUFFERING;
}

void ctap_hid_init(void)
{
    mutex_init(&is_busy_mutex);
    worker_pid = thread_create(worker_stack, sizeof(worker_stack), THREAD_PRIORITY_MAIN -2,
                               THREAD_CREATE_SLEEPING, pkt_worker, NULL, "ctap_hid_pkt_worker");
}

void ctap_hid_handle_packet(uint8_t* pkt_raw)
{
    ctap_hid_pkt_t *pkt = (ctap_hid_pkt_t*)pkt_raw;
    uint32_t cid = pkt->cid;
    uint8_t status = CTAP_HID_BUFFER_STATUS_BUFFERING;

    DEBUG("ctap_hid_handle_packet: 0x%08lx \n", cid);

    mutex_lock(&is_busy_mutex);

    if (is_busy) {
        if (pkt->cid == 0x00) {
            /* cid = 0x00 always invalid */
            send_error_response(pkt->cid, CTAP_HID_ERROR_INVALID_CHANNEL);
            return;
        }
        else if (ctap_hid_buffer.cid == cid) {
            /* only cont packets allowed once init packet has been received */
            if (is_init_pkt(pkt)) {
                send_error_response(pkt->cid, CTAP_HID_ERROR_INVALID_SEQ);
                return;
            }
            /* packet for this cid is currently being worked */
            if (ctap_hid_buffer.locked) {
                send_error_response(pkt->cid, CTAP_HID_ERROR_CHANNEL_BUSY);
                return;
            }
            /* buffer cont packets */
            status = buffer_pkt(pkt);
        }
        /* transactions are atomic, deny all other cids if busy with one cid */
        else {
            send_error_response(pkt->cid, CTAP_HID_ERROR_CHANNEL_BUSY);
            return;
        }
    }
    else {
        /* first init packet received starts a transaction */
        if (is_init_pkt(pkt)) {
            is_busy = 1;
            status = buffer_pkt(pkt);
        }
        /* ignore rest */
    }

    if (status == CTAP_HID_BUFFER_STATUS_ERROR) {
        memset(&ctap_hid_buffer, 0, sizeof(ctap_hid_buffer));
        send_error_response(cid, ctap_hid_buffer.err);
    }
    /* pkt->init.bcnt bytes have been received. Wakeup worker */
    else if (status == CTAP_HID_BUFFER_STATUS_DONE) {
        /*todo: mutex needed here too? */
        ctap_hid_buffer.locked = 1;
        mutex_unlock(&is_busy_mutex);
        thread_wakeup(worker_pid);
    }

    mutex_unlock(&is_busy_mutex);
}

static void* pkt_worker(void* arg)
{
    (void) arg;

    while (1) {

        uint8_t* buf = (uint8_t*) &ctap_hid_buffer.buffer;
        uint32_t cid = ctap_hid_buffer.cid;
        uint16_t bcnt = ctap_hid_buffer.bcnt;
        uint8_t cmd = ctap_hid_buffer.cmd;

        if (cmd == CTAP_HID_COMMAND_INIT) {
            DEBUG("CTAP_HID: INIT COMMAND \n");
            cid = handle_init_packet(cid, bcnt, buf);
        }
        else {
            /* broadcast cid only allowed for CTAP_HID_COMMAND_INIT */
            if (cid == CTAP_HID_BROADCAST_CID || cid == 0) {
                send_error_response(cid, CTAP_HID_ERROR_INVALID_CHANNEL);
            }
             /* readding deleted cid */
             /* todo: would it be possible to steal a channel ? */
            else if (!cid_exists(cid) && add_cid(cid) == -1) {
                send_error_response(cid, CTAP_HID_ERROR_CHANNEL_BUSY);
            }
            else {
                switch(cmd) {
                    case CTAP_HID_COMMAND_CBOR:
                        DEBUG("CTAP_HID: CBOR COMMAND \n");
                        handle_cbor_packet(cid, bcnt, cmd, buf);
                        break;
                    case CTAP_HID_COMMAND_WINK:
                        DEBUG("CTAP_HID: wink \n");
                        wink(cid, cmd);
                        break;
                    case CTAP_HID_COMMAND_PING:
                        DEBUG("CTAP_HID: PING \n");
                        ctap_hid_write(cmd, cid, buf, bcnt);
                        break;
                    case CTAP_HID_COMMAND_CANCEL:
                        DEBUG("CTAP_HID: cancel \n");
                        break;
                    default:
                        DEBUG("Ctaphid: unknown command \n");
                }
            }
        }

        /* transaction done, cleanup */
        /**
         * Cid deleted here in order to free up cid space.
         * Cid will be readded if an init paket with a cid not in the buffer is received.
         */
        /*todo: implement timeout to handle deletion of cids */
        if (cid) {
            delete_cid(cid);
        }
        memset(&ctap_hid_buffer, 0, sizeof(ctap_hid_buffer));

        mutex_lock(&is_busy_mutex);
        is_busy = 0;
        mutex_unlock(&is_busy_mutex);

        thread_sleep();
    }

    return (void*)0;
}

static void wink(uint32_t cid, uint8_t cmd)
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

    ctap_hid_write(cmd, cid, NULL, 0);
}

/* CTAP specification (version 20190130) section 8.1.9.1.3 */
static uint32_t handle_init_packet(uint32_t cid, uint16_t bcnt, uint8_t* payload)
{
    uint32_t cid_new = 0;

    /* cid 0 is reserved */
    if (cid == 0) {
        send_error_response(cid, CTAP_HID_ERROR_INVALID_CHANNEL);
        return 0;
    }
    /* check for len described in standard */
    if (bcnt != 8)
    {
        send_error_response(cid, CTAP_HID_ERROR_INVALID_LEN);
        return 0;
    }

    /* create new channel */
    if (cid == CTAP_HID_BROADCAST_CID) {
        cid_new = get_new_cid();
        if (add_cid(cid_new) == -1) {
            send_error_response(cid, CTAP_HID_ERROR_CHANNEL_BUSY);
            return 0;
        }
        send_init_response(cid, cid_new, payload);
    }
    /* synchronize channel */
    else {
        cid_new = cid;
        if (!cid_exists(cid)) {
            if (add_cid(cid) == -1) {
                /* reached cid limit */
                send_error_response(cid, CTAP_HID_ERROR_CHANNEL_BUSY);
                return 0;
            }
        }
        send_init_response(cid, cid, payload);
    }

    return cid_new;
}

/* CTAP specification (version 20190130) section 8.1.9.1.2 */
static void handle_cbor_packet(uint32_t cid, uint16_t bcnt, uint8_t cmd, uint8_t* payload)
{
    ctap_resp_t resp;
    uint8_t err;
    size_t size;

    if (bcnt == 0) {
        err = CTAP_HID_ERROR_INVALID_LEN;
        cmd = CTAP_HID_COMMAND_ERROR;
        ctap_hid_write(cmd, cid, &err, sizeof(err));
        return;
    }

    memset(&resp, 0, sizeof(ctap_resp_t));
    size = ctap_handle_request(payload, &resp);

    if (resp.status == CTAP2_OK) {
        ctap_hid_write(cmd, cid, &resp, size + sizeof(uint8_t));
    }
    else {
        ctap_hid_write(cmd, cid, &resp.status, sizeof(uint8_t));
    }
}

static void send_error_response(uint32_t cid, uint8_t err)
{
    DEBUG("CTAP_HID ERR RESPONSE: %02x \n", err);
    ctap_hid_write(CTAP_HID_COMMAND_ERROR, cid, &err, sizeof(err));
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
