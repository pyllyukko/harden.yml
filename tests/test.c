#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/*
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
*/
#include <libpamtest.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif

#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

uint8_t testcase = PAMTEST_ERR_OK;

static void test_pam_authenticate(void **state)
{
	enum pamtest_err perr;
	struct pamtest_conv_data conv_data;
	const char *trinity_authtoks[] = {
		"rootsecret",
		NULL,
	};
	struct pam_testcase tests[] = {
		pam_test(PAMTEST_AUTHENTICATE, PAM_SUCCESS),
	};

	(void) state;	/* unused */

	ZERO_STRUCT(conv_data);
	conv_data.in_echo_off = trinity_authtoks;

	perr = run_pamtest("login", "root", &conv_data, tests);
	assert_int_equal(perr, testcase);
}
void usage(void) {
  printf("\
options:\n\
	-h	this help\n\
	-r int	expected return code\n\
		return codes:\n\
		0	PAMTEST_ERR_OK\n\
		1	PAMTEST_ERR_START\n\
		2	PAMTEST_ERR_CASE\n\
		3	PAMTEST_ERR_OP\n\
		4	PAMTEST_ERR_END\n\
		5	PAMTEST_ERR_KEEPHANDLE\n\
		6	PAMTEST_ERR_INTERNAL\n\
");
}
int main(int argc, char *argv[]) {
    int rc, c;

    while((c = getopt (argc, argv, "hr:")) != -1) {
      switch(c) {
	case 'h':
	  usage();
	  exit(0);
	  break;
	case 'r':
	  testcase = atoi(optarg);
	  if(testcase>PAMTEST_ERR_INTERNAL) {
	    printf("invalid value\n");
	    exit(0);
	  }
	  break;
      }
    }
    const struct CMUnitTest init_tests[] = {
		cmocka_unit_test(test_pam_authenticate),
	};

    rc = cmocka_run_group_tests(init_tests, NULL, NULL);

    return rc;
}
