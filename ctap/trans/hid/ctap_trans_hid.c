#include <string.h>

#ifdef CONFIG_CTAP_NATIVE
#include <sys/time.h>
#endif

#include "xtimer.h"
#include "cbor.h"

#include "ctap_trans_hid.h"
#include "ctap_trans.h"
#include "ctap.h"
#include "ctap_utils.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static const uint8_t report_desc_ctap[] = {
  0x06, 0xD0, 0xF1, // HID_UsagePage ( FIDO_USAGE_PAGE ),
  0x09, 0x01, // HID_Usage ( FIDO_USAGE_CTAPHID ),
  0xA1, 0x01, // HID_Collection ( HID_Application ),
  0x09, 0x20, // HID_Usage ( FIDO_USAGE_DATA_IN ),
  0x15, 0x00, // HID_LogicalMin ( 0 ),
  0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
  0x75, 0x08, // HID_ReportSize ( 8 ),
  0x95, 0x40, // HID_ReportCount ( HID_INPUT_REPORT_BYTES ),
  0x81, 0x02, // HID_Input ( HID_Data | HID_Absolute | HID_Variable ),
  0x09, 0x21, // HID_Usage ( FIDO_USAGE_DATA_OUT ),
  0x15, 0x00, // HID_LogicalMin ( 0 ),
  0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
  0x75, 0x08, // HID_ReportSize ( 8 ),
  0x95, 0x40, // HID_ReportCount ( HID_OUTPUT_REPORT_BYTES ),
  0x91, 0x02, // HID_Output ( HID_Data | HID_Absolute | HID_Variable ),
  0xC0, // HID_EndCollection
};

//todo: how many concurrent devices should be allowed ?
static ctap_hid_cid_t cids[CTAP_HID_CIDS_MAX];

static bool is_init_type_pkt(const ctap_hid_pkt_t* pkt);

static ctap_hid_buffer_t ctap_buffer;

static uint8_t buffer_pkt(const ctap_hid_pkt_t *pkt);

static void send_error_response(uint32_t cid, uint8_t err);
static void ctap_hid_write(uint8_t cmd, uint32_t cid, const void* _data, size_t size);

static void handle_cbor_packet(uint32_t cid, uint16_t bcnt, uint8_t cmd, uint8_t* payload);
static void wink(uint32_t cid, uint8_t cmd);

static uint32_t handle_init_packet(uint32_t cid, uint16_t bcnt,
                                   const uint8_t* nonce);
static void send_init_response(uint32_t cid_old, uint32_t cid_new,
                               const uint8_t* nonce);

static int8_t refresh_cid(uint32_t cid);
static int8_t add_cid(uint32_t cid);
static int8_t delete_cid(uint32_t cid);
static bool cid_exists(uint32_t cid);
static uint32_t get_new_cid(void);
static uint16_t get_packet_len(const ctap_hid_pkt_t* pkt);

static void pkt_worker(void);

static void reset_ctap_buffer(void);

static bool is_busy = false;

static bool is_init_type_pkt(const ctap_hid_pkt_t *pkt)
{
    return ((pkt->init.cmd & CTAP_HID_INIT_PACKET) == CTAP_HID_INIT_PACKET);
}

static void reset_ctap_buffer(void)
{
    memset(&ctap_buffer, 0, sizeof(ctap_buffer));
}

static bool should_cancel(void)
{
    return ctap_buffer.should_cancel;
}

void ctap_trans_hid_check_timeouts(void)
{
    uint64_t now = xtimer_now_usec64();
    for (uint8_t i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        /* transaction timed out because cont packets didnt arrive in time */
        if (is_busy && cids[i].taken &&
            (now - cids[i].last_used) >= CTAP_HID_TRANSACTION_TIMEOUT &&
            ctap_buffer.cid == cids[i].cid && !ctap_buffer.is_locked) {

            send_error_response(cids[i].cid, CTAP_HID_ERR_MSG_TIMEOUT);
            delete_cid(cids[i].cid);
            reset_ctap_buffer();

            is_busy = false;
        }
    }
}

static uint32_t get_new_cid(void)
{
    /* channel id 0 is reserved */
    static uint32_t cid = 1;

    return cid++;
}

static int8_t add_cid(uint32_t cid)
{
    uint64_t oldest = xtimer_now_usec64();
    int8_t index_oldest = -1;

    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (!cids[i].taken) {
            cids[i].taken = 1;
            cids[i].cid = cid;
            cids[i].last_used = xtimer_now_usec64();

            return CTAP_HID_OK;
        }

        if (cids[i].last_used < oldest) {
            oldest = cids[i].last_used;
            index_oldest = i;
        }
    }

     /* remove oldest cid to make place for a new one (LIFO) */
    if (index_oldest > -1) {
        cids[index_oldest].taken = 1;
        cids[index_oldest].cid = cid;
        cids[index_oldest].last_used = xtimer_now_usec64();
        return CTAP_HID_OK;
    }

    return CTAP_HID_ERR_OTHER;
}

static int8_t refresh_cid(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            cids[i].last_used = xtimer_now_usec64();
            return CTAP_HID_OK;
        }
    }
    return CTAP_HID_ERR_OTHER;
}

static int8_t delete_cid(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            cids[i].taken = 0;
            cids[i].cid = 0;

            return CTAP_HID_OK;
        }
    }
    return CTAP_HID_ERR_OTHER;
}

static bool cid_exists(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            return true;
        }
    }
    return false;
}

static uint16_t get_packet_len(const ctap_hid_pkt_t* pkt)
{
    return (uint16_t)((pkt->init.bcnth << 8) | pkt->init.bcntl);
}

void ctap_trans_hid_create(void)
{
    ctap_trans_create(CTAP_TRANS_USB , report_desc_ctap, sizeof(report_desc_ctap));
}

static uint8_t buffer_pkt(const ctap_hid_pkt_t *pkt)
{
    if (is_init_type_pkt(pkt)) {
        /* received should_cancel for cid being buffered atm, should_cancel as
           long as worker not awoken */
        if (pkt->init.cmd == CTAP_HID_COMMAND_CANCEL && !ctap_buffer.is_locked &&
            pkt->cid == ctap_buffer.cid) {

            ctap_buffer.err = CTAP2_ERR_KEEPALIVE_CANCEL;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        ctap_buffer.bcnt = get_packet_len(pkt);

        /* check for init transaction size described in CTAP specification
           (version 20190130) section 8.1.9.1.3 */
        if (pkt->init.cmd == CTAP_HID_COMMAND_INIT && ctap_buffer.bcnt != 8) {
            ctap_buffer.err = CTAP_HID_ERR_INVALID_LEN;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        /* don't allow transactions bigger than max buffer size */
        if (ctap_buffer.bcnt > CTAP_HID_BUFFER_SIZE) {
            ctap_buffer.err = CTAP_HID_ERR_INVALID_LEN;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        uint16_t size = (ctap_buffer.bcnt < CTAP_HID_INIT_PAYLOAD_SIZE) ?
                        ctap_buffer.bcnt : CTAP_HID_INIT_PAYLOAD_SIZE;
        ctap_buffer.cmd = pkt->init.cmd;
        ctap_buffer.cid = pkt->cid;
        ctap_buffer.seq = -1;
        memmove(ctap_buffer.buffer, pkt->init.payload, size);
        ctap_buffer.offset = size;
    }
    else {
        int left = ctap_buffer.bcnt - ctap_buffer.offset;
        int diff = left - CTAP_HID_CONT_PAYLOAD_SIZE;
        ctap_buffer.seq++;

        /* seqs have to increase sequentially */
        if (pkt->cont.seq != ctap_buffer.seq) {
            ctap_buffer.err = CTAP_HID_ERR_INVALID_SEQ;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        /* check for potential buffer overflow */
        if (ctap_buffer.offset + CTAP_HID_CONT_PAYLOAD_SIZE > CTAP_HID_BUFFER_SIZE) {
            ctap_buffer.err = CTAP_HID_ERR_INVALID_LEN;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        if (diff <= 0) {
            memmove(ctap_buffer.buffer + ctap_buffer.offset, pkt->cont.payload, left);
            ctap_buffer.offset += left;
        }
        else {
            memmove(ctap_buffer.buffer + ctap_buffer.offset, pkt->cont.payload,
            CTAP_HID_CONT_PAYLOAD_SIZE);
            ctap_buffer.offset += CTAP_HID_CONT_PAYLOAD_SIZE;
        }
    }

    return ctap_buffer.offset == ctap_buffer.bcnt ?
           CTAP_HID_BUFFER_STATUS_DONE : CTAP_HID_BUFFER_STATUS_BUFFERING;
}

void ctap_trans_hid_handle_packet(void *pkt_raw)
{
    ctap_hid_pkt_t *pkt = (ctap_hid_pkt_t*)pkt_raw;
    uint32_t cid = pkt->cid;
    uint8_t status = CTAP_HID_BUFFER_STATUS_BUFFERING;

    if (cid == 0x00) {
        /* cid = 0x00 always invalid */
        send_error_response(cid, CTAP_HID_ERR_INVALID_CHANNEL);
    }
    else if(is_busy) {
        if (ctap_buffer.cid == cid) {
            /* CTAP specification (version 20190130) section 8.1.5.3 */
            if (is_init_type_pkt(pkt)) {
                if (pkt->init.cmd == CTAP_HID_COMMAND_INIT) {
                    /* abort */
                    DEBUG("Abort \n");
                    reset_ctap_buffer();
                    status = buffer_pkt(pkt);
                }
                else if (ctap_buffer.is_locked && pkt->init.cmd ==
                         CTAP_HID_COMMAND_CANCEL) {
                    ctap_buffer.should_cancel = true;
                }
                /* random init type pkt. invalid sequence of pkts */
                else {
                    send_error_response(cid, CTAP_HID_ERR_INVALID_SEQ);
                }
            }
            /* packet for this cid is currently being worked */
            else if (ctap_buffer.is_locked) {
                send_error_response(cid, CTAP_HID_ERR_CHANNEL_BUSY);
            }
            else {
                /* buffer cont packets */
                status = buffer_pkt(pkt);
            }
        }
        /* transactions are atomic, deny all other cids if busy with one cid */
        else {
            send_error_response(cid, CTAP_HID_ERR_CHANNEL_BUSY);
        }
    }
    else {
        /* first init packet received starts a transaction */
        if (is_init_type_pkt(pkt)) {
            is_busy = true;
            status = buffer_pkt(pkt);
        }
        /* ignore rest */
    }

    if (status == CTAP_HID_BUFFER_STATUS_ERROR) {
        send_error_response(cid, ctap_buffer.err);
        delete_cid(cid);
        reset_ctap_buffer();
        is_busy = false;
    }
    /* pkt->init.bcnt bytes have been received. Wakeup worker */
    else if (status == CTAP_HID_BUFFER_STATUS_DONE) {
        ctap_buffer.is_locked = 1;
        pkt_worker();
        is_busy = false;
    }
    else {
        /* refresh timestamp of cid that is being buffered */
        refresh_cid(ctap_buffer.cid);
    }
}

static void pkt_worker(void)
{
    uint8_t* buf = (uint8_t*) &ctap_buffer.buffer;
    uint32_t cid = ctap_buffer.cid;
    uint16_t bcnt = ctap_buffer.bcnt;
    uint8_t cmd = ctap_buffer.cmd;

    if (cmd == CTAP_HID_COMMAND_INIT) {
        cid = handle_init_packet(cid, bcnt, buf);
    }
    else {
        /* broadcast cid only allowed for CTAP_HID_COMMAND_INIT */
        if (cid == CTAP_HID_BROADCAST_CID || cid == 0) {
            send_error_response(cid, CTAP_HID_ERR_INVALID_CHANNEL);
        }
         /* readding deleted cid */
         /* todo: would it be possible to steal a channel ? */
        else if (!cid_exists(cid) && add_cid(cid) == -1) {
            send_error_response(cid, CTAP_HID_ERR_CHANNEL_BUSY);
        }
        else {
            switch(cmd) {
                case CTAP_HID_COMMAND_MSG:
                    /* not implemented */
                    DEBUG("CTAP_HID: MSG COMMAND \n");
                    send_error_response(cid, CTAP_HID_ERR_INVALID_CMD);
                    break;
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
                    /*
                     * no transaction is currently being processed,
                     * no reason to send cancel
                     */
                    break;
                default:
                    send_error_response(cid, CTAP_HID_ERR_INVALID_CMD);
                    DEBUG("Ctaphid: unknown command %u \n", cmd);
            }
        }
    }

    /* transaction done, cleanup */
    reset_ctap_buffer();
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
static uint32_t handle_init_packet(uint32_t cid, uint16_t bcnt,
                                   const uint8_t* nonce)
{
    uint32_t cid_new = 0;

    /* cid 0 is reserved */
    if (cid == 0) {
        send_error_response(cid, CTAP_HID_ERR_INVALID_CHANNEL);
        return 0;
    }
    /* check for len described in standard */
    if (bcnt != 8)
    {
        send_error_response(cid, CTAP_HID_ERR_INVALID_LEN);
        return 0;
    }
    /* create new channel */
    if (cid == CTAP_HID_BROADCAST_CID) {
        cid_new = get_new_cid();
        if (add_cid(cid_new) == -1) {
            send_error_response(cid, CTAP_HID_ERR_CHANNEL_BUSY);
            return 0;
        }
        send_init_response(cid, cid_new, nonce);
    }
    /* synchronize channel */
    else {
        cid_new = cid;
        if (!cid_exists(cid)) {
            if (add_cid(cid) == -1) {
                /* reached cid limit */
                send_error_response(cid, CTAP_HID_ERR_CHANNEL_BUSY);
                return 0;
            }
        }
        send_init_response(cid, cid, nonce);
    }

    return cid_new;
}

/* CTAP specification (version 20190130) section 8.1.9.1.2 */
static void handle_cbor_packet(uint32_t cid, uint16_t bcnt, uint8_t cmd,
                               uint8_t* payload)
{
    ctap_resp_t resp;
    uint8_t err;
    size_t size;
    uint8_t type = *payload;

    if (bcnt == 0) {
        err = CTAP_HID_ERR_INVALID_LEN;
        cmd = CTAP_HID_COMMAND_ERROR;
        ctap_hid_write(cmd, cid, &err, sizeof(err));
        return;
    }

    memset(&resp, 0, sizeof(ctap_resp_t));

    timestamp();
    size = ctap_handle_request(payload, bcnt, &resp, &should_cancel);

    DEBUG("ctap_trans_hid cbor operation took: %u usec type: %u \n", timestamp(), type);

    if (resp.status == CTAP2_OK && size > 0) {
        /* status + data */
        ctap_hid_write(cmd, cid, &resp, size + sizeof(resp.status));
    }
    else {
        /* status only */
        ctap_hid_write(cmd, cid, &resp.status, sizeof(resp.status));
    }
}

void ctap_trans_hid_send_keepalive(uint8_t status)
{
    ctap_hid_write(CTAP_HID_COMMAND_KEEPALIVE, ctap_buffer.cid, &status,
                   sizeof(status));
}

static void send_error_response(uint32_t cid, uint8_t err)
{
    DEBUG("ctap_trans_hid err resp: %02x \n", err);
    ctap_hid_write(CTAP_HID_COMMAND_ERROR, cid, &err, sizeof(err));
}

static void send_init_response(uint32_t cid_old, uint32_t cid_new,
                               const uint8_t* nonce)
{
    DEBUG("ctap_trans_hid: send_init_response %lu %lu\n ", cid_old, cid_new);

    ctap_hid_init_resp_t resp;
    memset(&resp, 0, sizeof(ctap_hid_init_resp_t));

    resp.cid = cid_new;
    memmove(resp.nonce, nonce, 8);
    resp.protocol_version = CTAP_HID_PROTOCOL_VERSION;
    resp.version_major = 0;
    resp.version_minor = 0;
    resp.build_version = 0;

    uint8_t cmd = (CTAP_HID_INIT_PACKET | CTAP_HID_COMMAND_INIT);

    resp.capabilities = CTAP_HID_CAPABILITY_CBOR | CTAP_HID_CAPABILITY_WINK
                        | CTAP_HID_CAPABILITY_NMSG;

    ctap_hid_write(cmd, cid_old, &resp, sizeof(ctap_hid_init_resp_t));
}

static void ctap_hid_write(uint8_t cmd, uint32_t cid, const void* _data, size_t size)
{
    const uint8_t* data = (uint8_t*)_data;
    uint8_t buf[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE];
    int offset = 0;
    int bytes_written = 0;
    uint8_t seq = 0;

    memmove(buf, &cid, sizeof(cid));
    offset += sizeof(cid);
    buf[offset++] = cmd;
    buf[offset++] = (size & 0xff00) >> 8;
    buf[offset++] = (size & 0xff) >> 0;

    if (data == NULL) {
        memset(buf + offset, 0, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE - offset);
        ctap_trans_write(CTAP_TRANS_USB, buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
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
        bytes_written++;

        if (offset == CONFIG_USBUS_HID_INTERRUPT_EP_SIZE) {
            ctap_trans_write(CTAP_TRANS_USB, buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
            offset = 0;
        }
    }

    if (offset > 0) {
        memset(buf + offset, 0, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE - offset);
         ctap_trans_write(CTAP_TRANS_USB, buf, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE);
    }
}