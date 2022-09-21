
#ifdef TON_UNIT_TESTS

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "filetransfer.h"
#include "netif.h"
#include "utils.h"

#define CALL_TEST_REG_FN(fn) { \
    CU_ErrorCode rc = fn(); \
    if (rc != 0) { \
        fprintf(stderr, "%s failed: CU_ErrorCode %d, last error message: %s\n", #fn, (int) rc, CU_get_error_msg()); \
        exit(1); \
    } \
}

/* Run unit tests, defined in their respective source files. */
int main_test(int argc, char **argv) {
    int exit_status = 0;
    CU_ErrorCode rc;

    CU_initialize_registry();

    CALL_TEST_REG_FN(ton_filetransfer_register_tests);
    CALL_TEST_REG_FN(ton_netif_register_tests);
    CALL_TEST_REG_FN(ton_utils_register_tests);
    CALL_TEST_REG_FN(ton_localfs_register_tests);

    rc = CU_basic_run_tests();

    if (rc != 0) {
        printf("Tests failed to run. CU_basic_run_tests() returned %d (%s)\n", rc, CU_get_error_msg());
        exit_status = 1;
    }
    else {
        exit_status = CU_get_number_of_tests_failed() != 0;
    }

    CU_cleanup_registry();

    return exit_status;
}

#endif
