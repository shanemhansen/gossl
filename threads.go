package gossl
/*
#include "openssl/ssl.h"
#include <pthread.h>

#cgo pkg-config: openssl

static pthread_mutex_t *lock_cs;
static long *lock_count;
unsigned long pthreads_thread_id(void)
	{
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
	}

void pthreads_locking_callback(int mode, int type, char *file,
	     int line)
      {
	if (mode & CRYPTO_LOCK)
		{
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
		}
	else
		{
		pthread_mutex_unlock(&(lock_cs[type]));
		}
	}
void thread_setup(void)
	{
	int i;

	lock_cs=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i=0; i<CRYPTO_num_locks(); i++)
		{
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL);
		}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
	}
int GoSSLInitializeThreads() {
 thread_setup();
 return 1;
}
*/
import "C"

var sslThreadsInitialized = C.GoSSLInitializeThreads()
