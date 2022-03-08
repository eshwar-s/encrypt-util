#ifndef _PCH_H_
#define _PCH_H_

// Headers

#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

// Error Handling Macros

#define verify(expr) \
    do { \
        retval = (expr); \
        if (retval != 0) { \
            fprintf( \
                stderr, \
                "ERROR: [%s(%d)]: %d", \
                __FUNCTION__, \
                __LINE__, \
                retval \
            ); \
            goto exit; \
        } \
    } while (0);

#define verify_bool(expr) \
    do { \
        if (!(expr)) { \
            retval = -1; \
            fprintf( \
                stderr, \
                "ERROR: [%s(%d)]", \
                __FUNCTION__, \
                __LINE__ \
            ); \
            goto exit; \
        } \
    } while (0);

#define verify_quiet(expr) \
    do { \
        retval = (expr); \
        if (retval != 0) { \
            goto exit; \
        } \
    } while (0);

#define verify_bool_quiet(expr) \
    do { \
        if (!(expr)) { \
            retval = -1; \
            goto exit; \
        } \
    } while (0);

#define verify_quit(expr) \
    do { \
        retval = (expr); \
        if (retval != 0) { \
            exit(retval); \
        } \
    } while (0);

#define verify_bool_quit(expr) \
    do { \
        if (!(expr)) { \
            exit(-1); \
        } \
    } while (0);

#define safe_fclose(expr) \
    do { \
        if ((expr) != NULL) { \
            fclose((expr)); \
            (expr) = NULL; \
        } \
    } while (0);

#define safe_free(expr) \
    do { \
        if ((expr) != NULL) { \
            free((expr)); \
            (expr) = NULL; \
        } \
    } while (0);

#endif // _PCH_H_
