#ifndef find_port_h
#define find_port_h

#include <mach/mach.h>

uint64_t find_port_address(mach_port_t port, int disposition);
uint64_t find_port_via_kmem_read(mach_port_t port);

#endif /* find_port_h */
