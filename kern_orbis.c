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

static void *saved_prison = 0;
static void *saved_rdir   = 0;
static void *saved_jdir   = 0;

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

static void
patch_ucred_1352(void *ucred, void *prison0) {
  if(!ucred) return;
  *(uint32_t *)(((char *)ucred) + 0x04) = 0;                      // CR_UID = 0
  *(uint32_t *)(((char *)ucred) + 0x08) = 0;                      // CR_RUID = 0
  *(uint32_t *)(((char *)ucred) + 0x0c) = 0;                      // CR_SVUID = 0
  *(uint32_t *)(((char *)ucred) + 0x10) = 1;                      // CR_NGROUPS = 1
  *(uint32_t *)(((char *)ucred) + 0x14) = 0;                      // CR_RGID = 0
  *(void **)(((char *)ucred) + 0x30) = prison0;                   // CR_PRISON = &prison0
  *(uint64_t *)(((char *)ucred) + 0x58) = 0x3800000000000007ULL;  // Syscore AuthID (fork izni)
  *(uint64_t *)(((char *)ucred) + 0x60) = 0xffffffffffffffffULL;  // CR_SCECAPS1 (attrs)
  *(uint64_t *)(((char *)ucred) + 0x68) = 0xffffffffffffffffULL;  // CR_SCECAPS0 (caps)
}

static int
kexec_jailbreak(struct thread *td, struct kexec_ctx *ctx) {
  struct ucred* cred = td->td_proc->p_ucred;
  struct filedesc* fd = td->td_proc->p_fd;
  unsigned char *base = &((unsigned char *)read_msr(0xC0000082))[-K1352_XFAST_SYSCALL];

  void *prison0 = (void *)&base[K1352_PRISON_0];
  void *rootvn  = *(void **)&base[K1352_ROOTVNODE];

  if(!saved_prison) saved_prison = *(void **)(((char *)cred) + 0x30);
  if(!saved_rdir)   saved_rdir   = *(void **)(((char *)fd) + 0x10);
  if(!saved_jdir)   saved_jdir   = *(void **)(((char *)fd) + 0x18);

  void *td_ucred = *(void **)(((char *)td) + 0x130);
  patch_ucred_1352(cred, prison0);
  if(td_ucred && td_ucred != (void *)cred) {
    patch_ucred_1352(td_ucred, prison0);
  }

  *(void **)(((char *)fd) + 0x10) = rootvn; // FD_RDIR = 0x10
  *(void **)(((char *)fd) + 0x18) = rootvn; // FD_JDIR = 0x18

  return 0;
}

uint64_t app_get_authid(void) { return 0x3800000000000007ULL; }
uint64_t app_get_capabilities(void) { return 0xffffffffffffffffULL; }
uint64_t app_get_attributes(void) { return 0xffffffffffffffffULL; }

int app_set_attributes(uint64_t val) {
  return orbis_syscall(SYS_kexec, kexec_jailbreak, 0x1352);
}
int app_set_authid(uint64_t val) { return 0; }
int app_set_capabilities(uint64_t val) { return 0; }

int
app_jailbreak(void) {
  if(orbis_syscall(SYS_kexec, kexec_jailbreak, 0x1352)) {
    return -1;
  }
  chdir("/");
  return 0;
}
