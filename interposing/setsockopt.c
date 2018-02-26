#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <sys/time.h>

int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    static int (*real_setsockopt)(int, int, int, const void*, socklen_t) = NULL;
    if (!real_setsockopt)
        real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

    struct timeval fixed;
    fixed.tv_sec = 5;
    fixed.tv_usec = 0;

    if (optname == SO_RCVTIMEO){
    	printf("Fixing setsockopt SO_RCVTIMEO to 5 seconds");
    	optval = &fixed;
	}	

    int p = real_setsockopt(sockfd, level, optname, optval, optlen);
    fprintf(stderr, "setsockopt(%d) %d = %d\n", sockfd, optname, (int)optval);
 
    return p;
}



