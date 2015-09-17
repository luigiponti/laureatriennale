#include <sys/time.h>
#include <stdio.h>

main (void) {

	struct timeval currentTime;

	gettimeofday(&currentTime,NULL);
	printf("%.6f\n",(double)currentTime.tv_sec+currentTime.tv_usec/1000000.0);

}
