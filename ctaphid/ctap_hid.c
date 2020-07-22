#define USB_H_USER_IS_RIOT_INTERNAL

#include <string.h>

#include "usb/usbus.h"
#include "ctap_hid.h"
#include "ctap.h"
#include "cbor.h"

#include "thread.h"

#include "xtimer.h"
#include "board.h"

#include "mutex.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static uint8_t report_desc_ctap[] = {
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

static uint8_t is_init_pkt(ctap_hid_pkt_t* pkt);

static ctap_hid_buffer_t ctap_buffer;

static kernel_pid_t worker_pid;

//todo: reduce buffer size !!
static char worker_stack[16384];
static void* pkt_worker(void* pkt_raw);

static char stack[2048];
static void* pkt_loop(void* arg);

static usbus_t usbus;
static char usb_stack[USBUS_STACKSIZE];

static uint8_t buffer_pkt(ctap_hid_pkt_t *pkt);

void usb_hid_stdio_init(usbus_t* usbus, uint8_t* report_desc, size_t report_desc_size);
ssize_t usb_hid_stdio_write(const void* buffer, size_t size);

static void send_init_response(uint32_t, uint32_t, uint8_t*);
static void send_error_response(uint32_t cid, uint8_t err);
static void ctap_hid_write(uint8_t cmd, uint32_t cid, void* _data, size_t size);

static uint32_t handle_init_packet(uint32_t cid, uint16_t bcnt, uint8_t* payload);
static void handle_cbor_packet(uint32_t cid, uint16_t bcnt, uint8_t cmd, uint8_t* payload);
static void wink(uint32_t cid, uint8_t cmd);
static void send_init_response(uint32_t cid_old, uint32_t cid_new, uint8_t* nonce);

static int8_t refresh_cid(uint32_t cid);
static int8_t add_cid(uint32_t cid);
static int8_t delete_cid(uint32_t cid);
static uint8_t cid_exists(uint32_t cid);
static uint32_t get_new_cid(void);
static uint16_t get_packet_len(ctap_hid_pkt_t* pkt);

static void reset_ctap_buffer(void);

static void check_timeouts(void);

int usb_hid_stdio_read_timeout(void* buffer, size_t size, uint32_t timeout);

static mutex_t is_busy_mutex;
static uint8_t is_busy = 0;

static uint8_t is_init_pkt(ctap_hid_pkt_t* pkt)
{
    return ((pkt->init.cmd & CTAP_HID_INIT_PACKET) == CTAP_HID_INIT_PACKET);
}

static void reset_ctap_buffer(void)
{
    memset(&ctap_buffer, 0, sizeof(ctap_buffer));
}

static void check_timeouts(void)
{
    uint64_t now = xtimer_now_usec64();
    for (uint8_t i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        /* transaction timed out because cont packets didnt arrive in time */
        if (cids[i].taken && (now - cids[i].last_used) >= CTAP_HID_TRANSACTION_TIMEOUT &&
            ctap_buffer.cid == cids[i].cid && !ctap_buffer.locked) {
            send_error_response(cids[i].cid, CTAP_HID_ERROR_MSG_TIMEOUT);
            delete_cid(cids[i].cid);
            reset_ctap_buffer();

            mutex_lock(&is_busy_mutex);
            is_busy = 0;
            mutex_unlock(&is_busy_mutex);
        }
        /* delete cid due to inactivity, todo: delete, and kick most inactive client when space needed */
        else if (cids[i].taken && (now - cids[i].last_used) >= CTAP_HID_INACTIVITY_TIMEOUT) {
            delete_cid(cids[i].cid);
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
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (!cids[i].taken) {
            cids[i].taken = 1;
            cids[i].cid = cid;
            cids[i].last_used = xtimer_now_usec64();

            return 0;
        }
    }
    return -1;
}

static int8_t refresh_cid(uint32_t cid)
{
    for (int i = 0; i < CTAP_HID_CIDS_MAX; i++) {
        if (cids[i].cid == cid) {
            cids[i].last_used = xtimer_now_usec64();
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
        ctap_buffer.bcnt = get_packet_len(pkt);

        /* check for init transaction size described in CTAP specification (version 20190130) section 8.1.9.1.3 */
        if (pkt->init.cmd == CTAP_HID_COMMAND_INIT && ctap_buffer.bcnt != 8) {
            ctap_buffer.err = CTAP_HID_ERROR_INVALID_LEN;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        /* don't allow transactions bigger than max buffer size */
        if (ctap_buffer.bcnt > CTAP_HID_BUFFER_SIZE) {
            ctap_buffer.err = CTAP_HID_ERROR_INVALID_LEN;
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
        ctap_buffer.seq += 1;

        /* seqs have to increase sequentially */
        if (pkt->cont.seq != ctap_buffer.seq) {
            ctap_buffer.err = CTAP_HID_ERROR_INVALID_SEQ;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        /* check for potential buffer overflow */
        if (ctap_buffer.offset + CTAP_HID_CONT_PAYLOAD_SIZE > CTAP_HID_BUFFER_SIZE) {
            ctap_buffer.err = CTAP_HID_ERROR_INVALID_LEN;
            return CTAP_HID_BUFFER_STATUS_ERROR;
        }

        if (diff <= 0) {
            memmove(ctap_buffer.buffer + ctap_buffer.offset, pkt->cont.payload, left);
            ctap_buffer.offset += left;
        }
        else {
            memmove(ctap_buffer.buffer + ctap_buffer.offset, pkt->cont.payload, CTAP_HID_CONT_PAYLOAD_SIZE);
            ctap_buffer.offset += CTAP_HID_CONT_PAYLOAD_SIZE;
        }
    }

    return ctap_buffer.offset == ctap_buffer.bcnt ?
           CTAP_HID_BUFFER_STATUS_DONE : CTAP_HID_BUFFER_STATUS_BUFFERING;
}

void ctap_hid_create(void)
{
    usbdev_t *usbdev = usbdev_get_ctx(0);
    assert(usbdev);
    usbus_init(&usbus, usbdev);
    usb_hid_stdio_init(&usbus, report_desc_ctap, sizeof(report_desc_ctap));

    DEBUG("Starting usbus thread \n");
    usbus_create(usb_stack, USBUS_STACKSIZE, USBUS_PRIO, USBUS_TNAME, &usbus);

    mutex_init(&is_busy_mutex);

    DEBUG("Creating ctap_hid main thread \n");
    thread_create(stack, sizeof(stack), THREAD_PRIORITY_MAIN -2, 0, pkt_loop,
                                NULL, "ctap_hid_main");

    DEBUG("Creating ctap_hid worker thread \n");
    worker_pid = thread_create(worker_stack, sizeof(worker_stack), THREAD_PRIORITY_MAIN -1,
                               THREAD_CREATE_SLEEPING, pkt_worker, NULL, "ctap_hid_pkt_worker");

}

void ctap_hid_handle_packet(uint8_t *pkt_raw)
{

    ctap_hid_pkt_t *pkt = (ctap_hid_pkt_t*)pkt_raw;
    uint32_t cid = pkt->cid;
    uint8_t status = CTAP_HID_BUFFER_STATUS_BUFFERING;

    mutex_lock(&is_busy_mutex);

    DEBUG("ctap_hid_handle_packet: 0x%08lx %d \n", cid, is_busy);

    if (cid == 0x00) {
        /* cid = 0x00 always invalid */
        send_error_response(cid, CTAP_HID_ERROR_INVALID_CHANNEL);
    }
    else if(is_busy) {
        if (ctap_buffer.cid == cid) {
            /*
             If the device detects an INIT command during a transaction that has the same channel id
             as the active transaction, the transaction is aborted (if possible)
             and all buffered data flushed (if any)
             */
            if (is_init_pkt(pkt)) {
                /* todo: reset when ctap_buffer is locked ? */
                if (!ctap_buffer.locked) {
                    delete_cid(cid);
                    reset_ctap_buffer();
                    is_busy = 0;
                }
                send_error_response(cid, CTAP_HID_ERROR_INVALID_SEQ);
            }
            /* packet for this cid is currently being worked */
            else if (ctap_buffer.locked) {
                send_error_response(cid, CTAP_HID_ERROR_CHANNEL_BUSY);
            }
            else {
                /* buffer cont packets */
                status = buffer_pkt(pkt);
            }
        }
        /* transactions are atomic, deny all other cids if busy with one cid */
        else {
            send_error_response(cid, CTAP_HID_ERROR_CHANNEL_BUSY);
        }
    }
    else {
        /* first init packet received, starts a transaction */
        if (is_init_pkt(pkt)) {
            is_busy = 1;
            status = buffer_pkt(pkt);
        }
        /* ignore rest */
    }

    if (status == CTAP_HID_BUFFER_STATUS_ERROR) {
        send_error_response(cid, ctap_buffer.err);
        delete_cid(cid);
        reset_ctap_buffer();
        is_busy = 0;
    }
    /* pkt->init.bcnt bytes have been received. Wakeup worker */
    else if (status == CTAP_HID_BUFFER_STATUS_DONE) {
        /*todo: mutex needed here too? */
        ctap_buffer.locked = 1;
        thread_wakeup(worker_pid);
    }
    else {
        /* refresh timestamp of cid that is being buffered */
        refresh_cid(ctap_buffer.cid);
    }

    mutex_unlock(&is_busy_mutex);
}

static void* pkt_loop(void* arg)
{
    (void) arg;
    uint8_t buffer[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE];
    int read;

    while (1) {
        read = usb_hid_stdio_read_timeout(buffer, CONFIG_USBUS_HID_INTERRUPT_EP_SIZE, CTAP_HID_TRANSACTION_TIMEOUT);

        if (read == CONFIG_USBUS_HID_INTERRUPT_EP_SIZE) {
            ctap_hid_handle_packet(buffer);
        }

        check_timeouts();
    }

    return (void*)0;
}

static void* pkt_worker(void* arg)
{
    (void) arg;

     /* init crypto stuff */
    ctap_init();

    while (1) {

        uint8_t* buf = (uint8_t*) &ctap_buffer.buffer;
        uint32_t cid = ctap_buffer.cid;
        uint16_t bcnt = ctap_buffer.bcnt;
        uint8_t cmd = ctap_buffer.cmd;

        DEBUG("PKT WORKER \n");

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
                    case CTAP_HID_COMMAND_MSG:
                        DEBUG("CTAP_HID: MSG COMMAND \n");
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
                        DEBUG("CTAP_HID: cancel \n");
                        break;
                    default:
                        DEBUG("Ctaphid: unknown command %u \n", cmd);
                }
            }
        }

        /* transaction done, cleanup */
        reset_ctap_buffer();

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
    size = ctap_handle_request(payload, bcnt, &resp);

    DEBUG("CTAPHID CBOR BYTES TO SENT: %u %u\n", size, resp.status);

    if (resp.status == CTAP2_OK) {
        /* status + data */
        ctap_hid_write(cmd, cid, &resp, size + sizeof(resp.status));
    }
    else {
        /* status only */
        ctap_hid_write(cmd, cid, &resp.status, sizeof(resp.status));
    }
}

void ctap_hid_send_keepalive(uint8_t status)
{
    ctap_hid_write(CTAP_HID_COMMAND_KEEPALIVE, ctap_buffer.cid, &status, sizeof(status));
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