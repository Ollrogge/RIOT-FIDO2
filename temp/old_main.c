#include <stdio.h>
#include "xtimer.h"
#include "usb/usbus.h"

#ifdef MODULE_USBUS_CDC_ECM
#include "usb/usbus/cdc/ecm.h"
static usbus_cdcecm_device_t cdcecm;
#endif
#ifdef MODULE_USBUS_HID
#include "usb/usbus/hid.h"
static usbus_hid_device_t hid;
#endif
#ifdef MODULE_USBUS_CDC_ACM
#include "usb/usbus/cdc/acm.h"
#endif
static usbus_t usbus;
static char _stack[USBUS_STACKSIZE];

int main(void) {

    xtimer_sleep(3);

    printf("Main enter \n");

    usbdev_t *usbdev = usbdev_get_ctx(0);
    assert(usbdev);

    usbus_init(&usbus, usbdev);

#ifdef MODULE_USBUS_HID
    printf("main: hid init\n");
    usbus_hid_device_init(&usbus, &hid);
#endif

#ifdef MODULE_STDIO_CDC_ACM
    printf("main: cdc_acm init \n");
    void usb_cdc_acm_stdio_init(usbus_t *usbus);
    usb_cdc_acm_stdio_init(&usbus);
#endif

#ifdef MODULE_USBUS_CDC_ECM
    printf("main: cdc init \n");
    usbus_cdcecm_init(&usbus, &cdcecm);
#endif

    printf("Starting usbus thread \n");

    usbus_create(_stack, USBUS_STACKSIZE, USBUS_PRIO, USBUS_TNAME, &usbus);

    for(;;) {
        printf("tick \n");

        xtimer_sleep(30);
    }
    

    return 0;
}
