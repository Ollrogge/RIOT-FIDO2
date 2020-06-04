
#define USB_H_USER_IS_RIOT_INTERNAL

#include "usb/usbus.h"
#include "hid_ctap.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"


void hid_ctap_handle_packet(uint8_t* pkt_raw)
{
    usb_ctap_hid_pkt *pkt = (usb_ctap_hid_pkt*)pkt_raw;

    // To allocate a new channel, the requesting application SHALL use the broadcast channel 
    // CTAPHID_BROADCAST_CID (0xFFFFFFFF)

    DEBUG("CTAP_HID: CID: %04lx \n", pkt->cid);
    DEBUG("CTAP_HID: cmd: %02x \n", pkt->pkt.init.cmd);
}