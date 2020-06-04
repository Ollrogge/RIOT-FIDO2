#ifndef USB_CTAP_HID_H
#define USB_CTAP_HID_H

#include <stdint.h>
#include "usb/usbus/hid.h"


#define CTAPHID_INIT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-7)
#define CTAPHID_CONT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-5)

#define USB_CTAP_HID_INIT 0x80
#define USB_CTAP_HID_CONT 0x00

void hid_ctap_handle_packet(uint8_t* pkt_raw);

typedef struct
{
    uint32_t cid;
    union{
        struct{
            uint8_t cmd;
            uint8_t bcnth;
            uint8_t bcntl;
            uint8_t payload[CTAPHID_INIT_PAYLOAD_SIZE];
        } init;
        struct{
            uint8_t seq;
            uint8_t payload[CTAPHID_CONT_PAYLOAD_SIZE];
        } cont;
    } pkt;
} usb_ctap_hid_pkt;

#endif