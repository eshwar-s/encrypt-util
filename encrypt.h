#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#include "pch.h"

typedef struct _encrypt_block_info
{
    unsigned int                    index;
    unsigned char*                  block;
    unsigned int                    length;
    struct _encrypt_block_info*     next;
}
encrypt_block_info_t, *pencrypt_block_info_t;

typedef struct _encrypt_context
{
    unsigned char           quit;               // flag to signal quit
    pthread_mutex_t         queuelock;          // queue lock for synchronization
    encrypt_block_info_t*   process_queue;      // queue containing blocks ready for processing
    encrypt_block_info_t*   completion_queue;   // queue containing blocks completed processing
    sem_t                   process_event;      // signal worker threads to start processing
    sem_t                   completion_event;   // signal to main thread about processing complete
    pthread_t*              threads;            // array of worker threads
    unsigned int            threadcount;        // number of worker threads
    unsigned char*          key;                // key read from the keyfile
    unsigned int            keylength;          // length of the keyfile
}
encrypt_context_t, *pencrypt_context_t;

int encrypt(char* keyfilename, unsigned int threadcount);

#endif // _ENCRYPT_H_