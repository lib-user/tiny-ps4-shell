#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include <orbis/libkernel.h>
#include <orbis/SysUtil.h>

#include "kern_orbis.h"

#ifndef TITLE_ID
#error missing TITLE_ID
#endif

#define INSTALL_DIR "/system/vsh/app/"TITLE_ID

static void orbis_notify(const char *fmt, ...) {
  OrbisNotificationRequest req;
  va_list args;
  bzero(&req, sizeof req);
  va_start(args, fmt);
  vsnprintf(req.message, sizeof req.message, fmt, args);
  va_end(args);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

static void build_iovec(struct iovec **iov, int *iovlen, const char *name, const char *val) {
  int i;
  if(*iovlen < 0) return;
  i = *iovlen;
  *iov = realloc(*iov, sizeof(**iov) * (i + 2));
  if(*iov == NULL) { *iovlen = -1; return; }
  (*iov)[i].iov_base = strdup(name);
  (*iov)[i].iov_len = strlen(name) + 1;
  i++;
  (*iov)[i].iov_base = val ? strdup(val) : NULL;
  (*iov)[i].iov_len = val ? strlen(val) + 1 : 0;
  i++;
  *iovlen = i;
}

static int mount_system() {
  struct iovec* iov = NULL;
  int iovlen = 0;
  build_iovec(&iov, &iovlen, "fstype", "exfatfs");
  build_iovec(&iov, &iovlen, "fspath", "/system");
  build_iovec(&iov, &iovlen, "from", "/dev/da0x4.crypt");
  build_iovec(&iov, &iovlen, "large", "yes");
  build_iovec(&iov, &iovlen, "timezone", "static");
  build_iovec(&iov, &iovlen, "async", NULL);
  build_iovec(&iov, &iovlen, "ignoreacl", NULL);
#define SYS_nmount 378
#define MNT_UPDATE 0x0000000000010000ULL
  return orbis_syscall(SYS_nmount, iov, iovlen, MNT_UPDATE);
}

static char* read_into_ram(const char *src_str, size_t *out_size) {
  struct stat s;
  int src = open(src_str, O_RDONLY, 0);
  if (src < 0) return NULL;
  bzero(&s, sizeof s);
  fstat(src, &s);
  if (!s.st_size) { close(src); return NULL; }
  char *buf = malloc(s.st_size);
  if (!buf) { close(src); return NULL; }
  if (read(src, buf, s.st_size) != s.st_size) {
    free(buf);
    close(src);
    return NULL;
  }
  close(src);
  *out_size = s.st_size;
  return buf;
}

static int write_from_ram(const char *dst_str, const char *buf, size_t size) {
  int dst = open(dst_str, O_CREAT | O_TRUNC | O_WRONLY, 0755);
  if (dst < 0) return -1;
  if (write(dst, buf, size) != (ssize_t)size) {
    close(dst);
    return -1;
  }
  close(dst);
  return 0;
}

static void install() {
  size_t eboot_sz = 0, param_sz = 0;

  // 1. Kum havuzundan çıkmadan ÖNCE /app0 içindeki dosyaları RAM'e oku!
  char *eboot_buf = read_into_ram("/app0/daemon/eboot.bin", &eboot_sz);
  char *param_buf = read_into_ram("/app0/daemon/param", &param_sz);

  if (!eboot_buf || !param_buf) {
    orbis_notify("Unable to read /app0/daemon files");
    return;
  }

  // 2. Şimdi 13.52 Jailbreak yap
  if (app_jailbreak()) {
    orbis_notify("Unable to escape jail");
    return;
  }

  if (seteuid(0)) {
    orbis_notify("Unable to acquire root permissions");
    return;
  }

  if (mount_system()) {
    orbis_notify("Unable to remount root partition");
    return;
  }

  if (mkdir(INSTALL_DIR, 0755) && errno != EEXIST) {
    orbis_notify("Unable to create install dir");
    return;
  }

  if (mkdir(INSTALL_DIR"/sce_sys", 0755) && errno != EEXIST) {
    orbis_notify("Unable to create install dir");
    return;
  }

  // 3. RAM'deki dosyaları doğrudan /system/vsh/app/BREW00009 içine yaz
  if (write_from_ram(INSTALL_DIR"/eboot.bin", eboot_buf, eboot_sz)) {
    orbis_notify("Unable to write " INSTALL_DIR "/eboot.bin");
    return;
  }

  if (write_from_ram(INSTALL_DIR"/sce_sys/param.sfo", param_buf, param_sz)) {
    orbis_notify("Unable to write param.sfo");
    return;
  }

  free(eboot_buf);
  free(param_buf);

  orbis_notify("Install successful");
}

int main() {
  install();
  while(1) { sleep(1); }
  return 0;
}
