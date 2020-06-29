#include <stdio.h>
#include <string.h>
#include "usb/usbus.h"
#include "xtimer.h"
#include "usb/usbus/hid.h"
#include "ctap_hid.h"
#include "thread.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

int main(void)
{

	xtimer_sleep(3);

	printf("Main enter \n");

  ctap_hid_create();

  return 0;
}