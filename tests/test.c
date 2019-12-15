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

#define SHOULDSUCCESS 0
#define SHOULDFAIL 1
uint8_t testcase = SHOULDSUCCESS;

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
	switch(testcase) {
		case SHOULDSUCCESS:
			assert_int_equal(perr, PAMTEST_ERR_OK);
			break;
		case SHOULDFAIL:
			assert_int_equal(perr, PAMTEST_ERR_CASE);
			break;
	}
}
int main(void) {
    int rc;
    /*
     * phases: 0 with Debian defaults
     *         1 modifications
     */
    switch(0) {
	case 0:
		testcase = SHOULDFAIL;
		break;
    }
    const struct CMUnitTest init_tests[] = {
		cmocka_unit_test(test_pam_authenticate),
	};

    rc = cmocka_run_group_tests(init_tests, NULL, NULL);

    return rc;
}
