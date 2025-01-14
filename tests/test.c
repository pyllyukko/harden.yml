#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
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

  perr = run_pamtest("login", "root", &conv_data, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_authenticate_nobody(void **state)
{
  enum pamtest_err perr;
  struct pamtest_conv_data conv_data;
  const char *trinity_authtoks[] = {
    "nobodysecret",
    NULL,
  };
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_AUTHENTICATE, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  ZERO_STRUCT(conv_data);
  conv_data.in_echo_off = trinity_authtoks;

  perr = run_pamtest("login", "nobody", &conv_data, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_authenticate_nobody_su(void **state)
{
  enum pamtest_err perr;
  struct pamtest_conv_data conv_data;
  const char *trinity_authtoks[] = {
    "nobodysecret",
    NULL,
  };
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_AUTHENTICATE, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  ZERO_STRUCT(conv_data);
  conv_data.in_echo_off = trinity_authtoks;

  perr = run_pamtest("su", "nobody", &conv_data, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_acct_invalid_user(void **state)
{
  enum pamtest_err perr;
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_ACCOUNT, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  perr = run_pamtest("login", "trinity", NULL, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_acct_root(void **state)
{
  enum pamtest_err perr;
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_ACCOUNT, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  perr = run_pamtest("login", "root", NULL, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_acct_cron_root(void **state)
{
  enum pamtest_err perr;
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_ACCOUNT, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  perr = run_pamtest("cron", "root", NULL, tests, NULL);
  assert_int_equal(perr, testcase);
}
static void test_pam_acct_cron_nobody(void **state)
{
  enum pamtest_err perr;
  struct pam_testcase tests[] = {
    pam_test(PAMTEST_ACCOUNT, PAM_SUCCESS),
  };

  (void) state;	/* unused */

  perr = run_pamtest("cron", "nobody", NULL, tests, NULL);
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
	-t int	test #\n\
		1	authenticate\n\
		2	login:acct invalid user\n\
		3	login:acct root user\n\
		4	cron:acct root user\n\
		5	cron:acct nobody user\n\
		6	login:auth nobody user\n\
		7	su:auth nobody user\n\
");
}
int main(int argc, char *argv[]) {
  int rc, c;
  void *ptr = NULL;

  while((c = getopt (argc, argv, "hr:t:")) != -1) {
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
      case 't':
        switch(atoi(optarg)) {
          case 1:
            ptr = test_pam_authenticate;
            break;
          case 2:
            ptr = test_pam_acct_invalid_user;
            break;
          case 3:
            ptr = test_pam_acct_root;
            break;
          case 4:
            ptr = test_pam_acct_cron_root;
            break;
          case 5:
            ptr = test_pam_acct_cron_nobody;
            break;
          case 6:
            ptr = test_pam_authenticate_nobody;
            break;
          case 7:
            ptr = test_pam_authenticate_nobody_su;
            break;
          default:
            printf("invalid test case\n");
            exit (1);
            break;
        }
        break;
    }
  }
  if(ptr==NULL) {
    printf("please specify a test case\n");
    exit(1);
  }
  const struct CMUnitTest init_tests[] = {
    cmocka_unit_test(ptr),
  };

  rc = cmocka_run_group_tests(init_tests, NULL, NULL);

  return rc;
}
