#include "encrypt.h"

// Forward Declarations

static void encrypt_rotate_key(unsigned char* key, unsigned int keylength, unsigned int shift);
static void encrypt_block(unsigned char* block, unsigned int length, unsigned char* key, unsigned int keylength);
static int encrypt_block_init(encrypt_block_info_t** blockinfo, unsigned int blockindex, unsigned int blocklength);
static void encrypt_block_deinit(encrypt_block_info_t* info);
static int encrypt_context_init(encrypt_context_t* context, unsigned char* key, unsigned int keylength, unsigned int threadcount);
static void encrypt_context_deinit(encrypt_context_t* context);
static int encrypt_execute(unsigned char* key, unsigned int keylength, unsigned int threadcount);

// Implementation

static void encrypt_rotate_key_bits(unsigned char* key, unsigned int keylength, unsigned char shift)
{
    unsigned int index = 0;
    unsigned char carry = 0;

    assert( key != NULL );
    
    for( ; shift > 0; shift-- )
    {
        carry = (key[0] & 0x80) != 0;

        for( index = 0; index < keylength; index++ )
        {
            key[index] <<= 1;

            if( (index+1) >= keylength )
                break;

            key[index] |= (key[index+1] & 0x80) != 0 ? 0x1 : 0x0;
        }

        key[keylength-1] |= carry ? 0x1 : 0x0;
    }
}

static unsigned int compute_gcd(unsigned int a, unsigned int b)
{
    if( b == 0 ) { return a; } return compute_gcd(b, a % b);
}

static void encrypt_rotate_key_bytes(unsigned char* key, unsigned int keylength, unsigned char shift)
{
    unsigned int index = 0, pos = 0, gcd = 0;
    unsigned char value = 0, next = 0;

    assert( key != NULL );
    assert( shift < keylength );

    gcd = compute_gcd( shift, keylength );

    for( index = 0; index < gcd; index++ )
    {
        value = key[index];
        pos = index;

        while( 1 )
        {
            next = pos + shift;

            if( next >= keylength )
                next = next - keylength;

            if( next == index )
                break;

            key[pos] = key[next];
            pos = next;
        }

        key[pos] = value;
    }
}

//
// To compute the rotated key, we do it in two phases. We first compute the byte
// shift amount which corresponds to rotating elements in an array. We use Bentley's algorithm
// to perform the shift inplace. The remaining shift amount which is less than 8 bits is done 
// one left shift at a time. Note to improve performance we could perform key caching and save
// computation for repetitive shift amounts since they are cyclic. This would make it performant
// for large number of blocks with small key sizes but this hasn't yet been implemented.
//
static void encrypt_rotate_key(unsigned char* key, unsigned int keylength, unsigned int shift)
{
    shift = shift % (keylength * 8);

    if( shift / 8 != 0 )
    {
        encrypt_rotate_key_bytes(key, keylength, shift / 8);
    }

    if( shift % 8 != 0 )
    {
        encrypt_rotate_key_bits(key, keylength, shift % 8);
    }
}

static void encrypt_block(unsigned char* block, unsigned int length, unsigned char* key, unsigned int keylength)
{
    unsigned int index = 0;

    assert( block != NULL );
    assert( key != NULL && length <= keylength );

    for( index = 0; index < length; index++ )
    {
        block[index] = block[index] ^ key[index];
    }
}

//
// Worker threads wait for process event from the main thread to signal event for processing.
// The worker then dequeues one block from the process queue and performs the encryption.
// Then when completed the worker enqueues the encrypted block to the completion queue and
// signals back to the worker about the completion of the encryption.
//
static void* encrypt_thread(void* arg)
{
    int retval = 0;
    unsigned char* key = NULL;
    encrypt_context_t* context = (encrypt_context_t*)arg;
    encrypt_block_info_t* info = NULL, *current = NULL, *previous = NULL;

    assert(context != NULL);

    verify_bool_quit( (key = (unsigned char*) malloc(context->keylength)) != NULL );

    while( !context->quit )
    {
        info = NULL;

        if( sem_wait(&context->process_event) != 0 )
            break;

        if( context->quit )
            break;

        pthread_mutex_lock( &context->queuelock );

        if( context->process_queue != NULL )
        {
            info = context->process_queue;
            context->process_queue = info->next;
        }

        pthread_mutex_unlock( &context->queuelock );

        if( info == NULL )
            continue;

        memcpy(key, context->key, context->keylength);
        encrypt_rotate_key(key, context->keylength, info->index);

        encrypt_block(info->block,
                      info->length,
                      key,
                      context->keylength);

        pthread_mutex_lock( &context->queuelock );

        for( current = context->completion_queue, previous = current;
             current != NULL;
             current = current->next )
        {
            if( info->index < current->index )
                break;

            previous = current;
        }

        if( context->completion_queue == NULL )
            context->completion_queue = info;
        else
            previous->next = info;

        info->next = current;
        pthread_mutex_unlock( &context->queuelock );

        sem_post( &context->completion_event );
    }

    pthread_exit(NULL);
    return NULL;
}

static int encrypt_block_init(encrypt_block_info_t** blockinfo, unsigned int blockindex, unsigned int blocklength)
{
    int retval = 0;
    encrypt_block_info_t* info = NULL;

    assert( blockinfo != NULL );
    assert( blocklength > 0 );

    *blockinfo = NULL;

    verify_bool( (info = (encrypt_block_info_t*) malloc( sizeof(encrypt_block_info_t) )) != NULL );

    memset( info, 0, sizeof(encrypt_block_info_t) );
    info->index = blockindex;

    verify_bool( (info->block = (unsigned char*) malloc( blocklength )) != NULL );

    info->length = blocklength;
    info->next = NULL;

    *blockinfo = info;
    info = NULL;

exit:
    encrypt_block_deinit( info );
    return retval;
}

static void encrypt_block_deinit(encrypt_block_info_t* info)
{
    int retval = 0;

    verify_bool_quiet( info != NULL );

    safe_free( info->block );
    safe_free( info );

exit:
    return;
}

static int encrypt_context_init(encrypt_context_t* context, unsigned char* key, unsigned int keylength, unsigned int threadcount)
{
    int retval = 0;
    unsigned int index = 0;

    context->key = key;
    context->keylength = keylength;

    verify( pthread_mutex_init(&context->queuelock, NULL) );

    verify( sem_init(&context->process_event, 0, 0) );
    verify( sem_init(&context->completion_event, 0, 0) );

    verify_bool( (context->threads = (pthread_t*) malloc( sizeof(pthread_t) * threadcount )) != NULL );

    context->threadcount = threadcount;
    memset( context->threads, 0, sizeof(pthread_t) * threadcount );

    for( index = 0; index < context->threadcount; index++ )
    {
        verify( pthread_create(&context->threads[index],
                               NULL,
                               encrypt_thread,
                               (void*) context) );
    }

exit:
    return retval;
}

static void encrypt_context_deinit(encrypt_context_t* context)
{
    int retval = 0;
    unsigned int index = 0;
    encrypt_block_info_t* current = NULL, *info = NULL;

    verify_bool_quiet( context != NULL );

    context->quit = 1;

    for( index = 0; index < context->threadcount; index++ )
    {
        sem_post( &context->process_event );
    }

    for( index = 0; index < context->threadcount; index++ )
    {
        pthread_join( context->threads[index], NULL );
    }

    for( current = context->completion_queue;
         current != NULL; )
    {
        info = current;
        current = current->next;
        encrypt_block_deinit( info );
    }

    for( current = context->process_queue;
         current != NULL; )
    {
        info = current;
        current = current->next;
        encrypt_block_deinit( info );
    }

    context->completion_queue = NULL;
    context->process_queue = NULL;

    sem_destroy( &context->completion_event );
    sem_destroy( &context->process_event );

    pthread_mutex_destroy( &context->queuelock );

exit:
    return;
}

//
// The main thread schedules each block read from the input stream to the worker
// thread. After N blocks are read and scheduled to the, worker thread to process
// the blocks are flushed to the output stream in order and the process continues
// until all blocks are read. The worker threads compute the rotated key based on
// the block index and perform the xor transformation. The worker thread and the main
// thread communicate using semaphore to signal.
//
static int encrypt_execute_parallel(unsigned char* key, unsigned int keylength, unsigned int threadcount)
{
    int retval = 0;
    unsigned int index = 0, slot = 0;
    unsigned char quit = 0;
    encrypt_context_t context;
    encrypt_block_info_t* info = NULL, *current = NULL;

    assert( key != NULL && keylength > 0 );
    assert( threadcount > 0 );

    memset( &context, 0, sizeof(encrypt_context_t) );
    verify( encrypt_context_init(&context, key, keylength, threadcount) );

    while( !quit )
    {
        for( slot = 0; slot < threadcount; index++, slot++ )
        {
            verify( encrypt_block_init(&info, index, keylength) );

            if( (info->length = fread(info->block, 1, keylength, stdin)) == 0 )
            {
                encrypt_block_deinit( info );
                quit = 1;
                break;
            }

            pthread_mutex_lock( &context.queuelock );

            if( context.process_queue == NULL )
                context.process_queue = info;
            else
            {
                for( current = context.process_queue;
                     current->next != NULL;
                     current = current->next )
                {}

                current->next = info;
            }

            pthread_mutex_unlock( &context.queuelock );
            sem_post( &context.process_event );
        }

        for( ; slot > 0; slot-- )
        {
            sem_wait( &context.completion_event );
        }

        pthread_mutex_lock( &context.queuelock );
        current = context.completion_queue;

        while( current != NULL )
        {
            info = current;
            current = current->next;
            fwrite(info->block, 1, info->length, stdout);
            encrypt_block_deinit( info );
        }

        context.completion_queue = NULL;
        pthread_mutex_unlock( &context.queuelock );
    }

exit:
    encrypt_context_deinit( &context );
    return retval;
}

static int encrypt_execute_sequential(unsigned char* key, unsigned int keylength)
{
    int retval = 0;
    unsigned int index = 0;
    encrypt_block_info_t* info = NULL;

    assert( key != NULL && keylength > 0 );

    verify( encrypt_block_init(&info, index, keylength) );

    for( index = 0;; index++ )
    {
        info->index = index;

        if( (info->length = fread(info->block, 1, keylength, stdin)) == 0 )
        {
            break;
        }

        encrypt_block(info->block,
                      info->length,
                      key,
                      keylength);

        fwrite(info->block, 1, info->length, stdout);
        encrypt_rotate_key(key, keylength, 1);
    }

exit:
    encrypt_block_deinit( info );
    return retval;
}

int encrypt(char* keyfilename, unsigned int threadcount)
{
    int retval = 0;
    unsigned int keylength = 0;
    unsigned char* key = NULL;
    FILE* keyfile = NULL;

    verify_bool( keyfilename != NULL );
    verify_bool( (keyfile = fopen(keyfilename, "rb")) != NULL );

    verify( fseek(keyfile, 0, SEEK_END) );
    verify_bool( (keylength = ftell(keyfile)) > 0 );
    verify( fseek(keyfile, 0, SEEK_SET) );

    verify_bool( (key = (unsigned char*) malloc(keylength)) );
    verify_bool( fread(key, 1, keylength, keyfile) > 0 );

    if( threadcount == 0 )
    {
        verify( encrypt_execute_sequential(key, keylength) );
    }
    else
    {
        verify( encrypt_execute_parallel(key, keylength, threadcount) );
    }

exit:
    safe_fclose( keyfile );
    safe_free( key );

    return retval;
}

void signal_handler(int signum)
{
    exit(signum);
}

int main(int argc, char* argv[])
{
    int index = 0;
    unsigned int threadcount = 0;
    char* keyfilename = NULL;

    for( index = 1; index < argc; index++ )
    {
        if( strcmp(argv[index], "-n") == 0 && (index+1) < argc )
        {
            threadcount = atoi(argv[++index]);
        }
        else if( strcmp(argv[index], "-k") == 0 && (index+1) < argc )
        {
            keyfilename = argv[++index];
        }
    }

    signal(SIGINT, &signal_handler);
    encrypt(keyfilename, threadcount);

    return 0;
}
