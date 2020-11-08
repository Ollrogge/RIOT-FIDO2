#include <stdio.h>
#include <string.h>
#include "xtimer.h"

#include "ctap.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

int main(void)
{
	xtimer_sleep(3);

	printf("Main enter \n");

  ctap_create();

  return 0;
}