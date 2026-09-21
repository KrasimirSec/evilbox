/* Return immediately so malware sleep() cannot stall the sandbox. */
#define _GNU_SOURCE
#include <time.h>
#include <unistd.h>

unsigned int sleep(unsigned int seconds) {
    (void)seconds;
    return 0;
}

int usleep(useconds_t usec) {
    (void)usec;
    return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)req;
    (void)rem;
    return 0;
}
