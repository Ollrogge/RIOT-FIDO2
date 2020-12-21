#include <stdio.h>
#include <string.h>
#include "xtimer.h"
#include "shell.h"
#include "shell_commands.h"

#include "ctap.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

int main(void)
{
	xtimer_sleep(3);

	printf("Main enter \n");

  ctap_create();

  char line_buf[SHELL_DEFAULT_BUFSIZE];
  shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

  return 0;
}