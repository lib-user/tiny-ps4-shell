#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <signal.h>
#include <fcntl.h>

#include "kern_orbis.h"
#include "sys.h"
#include "shell.h"

#ifdef __ORBIS__
#undef SO_REUSEADDR
#define SO_REUSEADDR 0x0004
#endif

static int
client_init(int fd) {
  for(int i=0; i<1024; i++) {
    if(i != fd && fcntl(i, F_GETFD) > 0 && errno != EBADF) {
      close(i);
    }
  }
  if(dup2(fd, STDIN_FILENO) < 0) return -1;
  if(dup2(fd, STDOUT_FILENO) < 0) return -1;
  if(dup2(fd, STDERR_FILENO) < 0) return -1;
  close(fd);
  return 0;
}

static void
client_handle_inproc(int slave) {
  int saved_in  = dup(STDIN_FILENO);
  int saved_out = dup(STDOUT_FILENO);
  int saved_err = dup(STDERR_FILENO);

  dup2(slave, STDIN_FILENO);
  dup2(slave, STDOUT_FILENO);
  dup2(slave, STDERR_FILENO);

  shell_loop();

  dup2(saved_in, STDIN_FILENO);
  dup2(saved_out, STDOUT_FILENO);
  dup2(saved_err, STDERR_FILENO);
  close(saved_in);
  close(saved_out);
  close(saved_err);
  close(slave);
}

static void
client_fork(int master, int slave) {
  pid_t pid = sys_fork();

  if (pid == 0) {
    close(master);
    if(client_init(slave)) {
      dprintf(slave, "init: %s", strerror(errno));
    } else {
      shell_loop();
    }
    _exit(0);
  } else if (pid < 0) {
    // fork desteklenmiyorsa bağlantıyı kapatma, doğrudan aynı süreçte çalıştır!
    client_handle_inproc(slave);
    return;
  }
  close(slave);
}

void serve_telnet(unsigned short port) {
  int sockfd;
  int connfd;
  socklen_t addr_len;
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    sys_notify("socket: %s", strerror(errno));
    return;
  }

  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    sys_notify("setsockopt: %s", strerror(errno));
    return;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    sys_notify("bind: %s", strerror(errno));
    return;
  }

  if(listen(sockfd, 5) != 0) {
    sys_notify("listen: %s", strerror(errno));
    return;
  }

  addr_len = sizeof(client_addr);
  while(1) {
    if((connfd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      sys_notify("accept: %s", strerror(errno));
      return;
    }
    client_fork(sockfd, connfd);
  }
}

int
main(void) {
  const int port = 2323;
  sys_init();
  app_jailbreak();
  seteuid(0);
  sys_notify("Serving telnet on port %d", port);

  sys_setprocname(TITLE_ID "(server)");
  signal(SIGCHLD, SIG_IGN);
  serve_telnet(port);

  while(1) {
    sleep(1);
  }
  return 0;
}
