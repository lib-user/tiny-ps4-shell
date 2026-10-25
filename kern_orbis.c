#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#include "kern_orbis.h"
#include "kern_orbis_types.h"
#include "kern_orbis_offsets.h"

#define SYS_kexec 11

static long
__syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  unsigned long ret;
  char iserror;

  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;

  __asm__ __volatile__(
     "syscall" : "=a"(ret), "=@ccc"(iserror), "+r"(r10), "+r"(r8), "+r"(r9) :
     "a"(n), "D"(a1), "S"(a2), "d"(a3) :
     "rcx", "r11", "memory"
     );

  return iserror ? -ret : ret;
}

long
orbis_syscall(long sysno, ...) {
  int  err;
  va_list args;
  long arg0, arg1, arg2, arg3, arg4, arg5;

  va_start(args, sysno);
  arg0 = va_arg(args, long);
  arg1 = va_arg(args, long);
  arg2 = va_arg(args, long);
  arg3 = va_arg(args, long);
  arg4 = va_arg(args, long);
  arg5 = va_arg(args, long);
  va_end(args);

  err = __syscall6(sysno, arg0, arg1, arg2, arg3, arg4, arg5);
  if(err < 0) {
    errno = -err;
    return -1;
  }

  return err;
}

static inline __attribute__((always_inline))
uint64_t read_msr(uint32_t reg) {
    uint32_t edx;
    uint32_t eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(reg));
    return (((uint64_t)edx) << 32) | (uint64_t)eax;
}

static int
kern_get_offsets(struct kern_offset *kern, unsigned int sw_ver) {
  void *base;
  unsigned char *ptr;

  kern->prison0 = 0;
  kern->root_vnode = 0;
  kern->copyin = 0;
  kern->copyout = 0;

  switch(sw_ver) {
  case 0x900:
    base = &((unsigned char *)read_msr(0xC0000082))[-K900_XFAST_SYSCALL];
    ptr = (unsigned char *)base;
    kern->prison0 = (void **)&ptr[K900_PRISON_0];
    kern->root_vnode = (void **)&ptr[K900_ROOTVNODE];
    kern->copyin = (void *)(base + K900_COPYIN);
    kern->copyout = (void *)(base + K900_COPYOUT);
    break;

  case 0x1352:
    base = &((unsigned char *)read_msr(0xC0000082))[-K1352_XFAST_SYSCALL];
    ptr = (unsigned char *)base;
    kern->prison0 = (void **)&ptr[K1352_PRISON_0];
    kern->root_vnode = (void **)&ptr[K1352_ROOTVNODE];
    kern->copyin = 0;
    kern->copyout = 0;
    break;

  default:
    return -1;
  }

  return 0;
}

static void
patch_ucred_1352(void *ucred, void *prison0) {
  if(!ucred) return;
  *(uint32_t *)(((char *)ucred) + 0x04) = 0;                      // CR_UID = 0
  *(uint32_t *)(((char *)ucred) + 0x08) = 0;                      // CR_RUID = 0
  *(uint32_t *)(((char *)ucred) + 0x0c) = 0;                      // CR_SVUID = 0
  *(uint32_t *)(((char *)ucred) + 0x10) = 1;                      // CR_NGROUPS = 1
  *(uint32_t *)(((char *)ucred) + 0x14) = 0;                      // CR_RGID = 0
  *(void **)(((char *)ucred) + 0x30) = prison0;                   // CR_PRISON = &prison0
  *(uint64_t *)(((char *)ucred) + 0x58) = 0x3801000000000013ULL;  // CR_SCEAUTHID
  *(uint64_t *)(((char *)ucred) + 0x60) = 0xffffffffffffffffULL;  // CR_SCECAPS1
  *(uint64_t *)(((char *)ucred) + 0x68) = 0xffffffffffffffffULL;  // CR_SCECAPS0
}

static int
kexec_jailbreak(struct thread *td, struct kexec_ctx *ctx) {
  struct ucred* cred = td->td_proc->p_ucred;
  struct filedesc* fd = td->td_proc->p_fd;
  struct kern_offset kern;

  kern_get_offsets(&kern, ctx->sw_ver);
  if(!kern.prison0 || !kern.root_vnode) {
    return EFAULT;
  }

  if(ctx->sw_ver == 0x1352) {
    void *td_ucred = *(void **)(((char *)td) + 0x130);
    patch_ucred_1352(cred, (void *)kern.prison0);
    if(td_ucred && td_ucred != (void *)cred) {
      patch_ucred_1352(td_ucred, (void *)kern.prison0);
    }

    void *rootvn = *(kern.root_vnode);
    *(void **)(((char *)fd) + 0x10) = rootvn; // FD_RDIR = 0x10
    *(void **)(((char *)fd) + 0x18) = rootvn; // FD_JDIR = 0x18
    return 0;
  }

  cred->cr_prison = *(kern.prison0);
  fd->fd_rdir = fd->fd_jdir = *(kern.root_vnode);

  return 0;
}

static int kexec_get_attributes(struct thread *td, struct kexec_ctx *ctx) { return 0; }
static int kexec_get_authid(struct thread *td, struct kexec_ctx *ctx) { return 0; }
static int kexec_get_capabilities(struct thread *td, struct kexec_ctx *ctx) { return 0; }
static int kexec_set_attributes(struct thread *td, struct kexec_ctx *ctx) { return 0; }
static int kexec_set_authid(struct thread *td, struct kexec_ctx *ctx) { return 0; }
static int kexec_set_capabilities(struct thread *td, struct kexec_ctx *ctx) { return 0; }

char* sceKernelGetFsSandboxRandomWord();

static unsigned int
libc_sw_version(void) {
  static unsigned int ver = 0;
  char path[PATH_MAX];
  int fd;

  if(ver) {
    return ver;
  }

  snprintf(path, sizeof(path), "/%s/%s", sceKernelGetFsSandboxRandomWord(),
                                         "common/lib/libc.sprx");

  if((fd = open(path, O_RDONLY)) < 0) {
    return 0;
  }

  lseek(fd, 0x374, SEEK_CUR);
  read(fd, &ver, 2);
  close(fd);

  return ver;
}

uint64_t app_get_authid(void) { return 0; }
uint64_t app_get_capabilities(void) { return 0; }
uint64_t app_get_attributes(void) { return 0; }
int app_set_attributes(uint64_t val) { return 0; }
int app_set_authid(uint64_t val) { return 0; }
int app_set_capabilities(uint64_t val) { return 0; }

int
app_jailbreak(void) {
  unsigned int sw_ver = libc_sw_version();
  if(orbis_syscall(SYS_kexec, kexec_jailbreak, sw_ver)) {
    return -1;
  }

  return 0;
}
