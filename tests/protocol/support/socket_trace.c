#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Linux/glibc test observer; never link this into the gateway. Metadata only,
 * original call exactly once, errno preserved. Direct syscalls bypass these
 * wrappers. Timestamps follow calls, except close-enter, which precedes close.
 * File IO and socket inspection perturb timing; this is not a kernel tracer. */
static int log_fd = -1;
__attribute__((constructor)) static void init_trace(void) {
  const char *p = getenv("AISP_SOCKET_TRACE");
  if (p) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, p,
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
      log_fd = (int)syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 1000);
      syscall(SYS_close, fd);
    }
  }
}
static void endpoint(const struct sockaddr_storage *s, char *out, size_t n) {
  char ip[INET6_ADDRSTRLEN] = "";
  if (s->ss_family == AF_INET) {
    const struct sockaddr_in *v = (const void *)s;
    inet_ntop(AF_INET, &v->sin_addr, ip, sizeof(ip));
    snprintf(out, n, "%s:%u", ip, ntohs(v->sin_port));
  } else if (s->ss_family == AF_INET6) {
    const struct sockaddr_in6 *v = (const void *)s;
    inet_ntop(AF_INET6, &v->sin6_addr, ip, sizeof(ip));
    snprintf(out, n, "[%s]:%u", ip, ntohs(v->sin6_port));
  } else
    snprintf(out, n, "family:%d", s->ss_family);
}
static void event_arg(const char *op, int fd, long ret, int error,
                      const struct sockaddr *target, socklen_t target_len,
                      int argument) {
  if (log_fd < 0)
    return;
  int saved = errno;
  struct sockaddr_storage local = {0}, peer = {0};
  socklen_t len = sizeof(local);
  if (syscall(SYS_getsockname, fd, &local, &len) < 0 ||
      (local.ss_family != AF_INET && local.ss_family != AF_INET6)) {
    errno = saved;
    return;
  }
  len = sizeof(peer);
  syscall(SYS_getpeername, fd, &peer, &len);
  if (target && target_len <= sizeof(peer)) {
    __builtin_memcpy(&peer, target, target_len);
  }
  char l[96], p[96], line[512];
  endpoint(&local, l, sizeof(l));
  endpoint(&peer, p, sizeof(p));
  struct timespec ts;
  syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
  struct stat st = {0}, parent = {0};
  syscall(SYS_fstat, fd, &st);
  if (argument >= 0 && (op[0] == 'a'))
    syscall(SYS_fstat, argument, &parent);
  int n = snprintf(
      line, sizeof(line),
      "{\"ns\":%lld,\"pid\":%d,\"tid\":%ld,\"op\":\"%s\",\"fd\":%d,\"inode\":%"
      "llu,\"local\":\"%s\",\"peer\":\"%s\",\"ret\":%ld,\"errno\":%d,"
      "\"family\":%d,\"peerFamily\":%d,\"arg\":%d,\"parentInode\":%llu}\n",
      (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec, getpid(),
      syscall(SYS_gettid), op, fd, (unsigned long long)st.st_ino, l, p, ret,
      error, local.ss_family, peer.ss_family, argument,
      (unsigned long long)parent.st_ino);
  if (n > 0 && n < (int)sizeof(line))
    syscall(SYS_write, log_fd, line, n);
  errno = saved;
}
static void event(const char *op, int fd, long ret, int error,
                  const struct sockaddr *target, socklen_t target_len) {
  event_arg(op, fd, ret, error, target, target_len, -1);
}
#define LOAD(name)                                                             \
  static _Thread_local __typeof__(&name) next;                                 \
  if (!next)                                                                   \
  next = dlsym(RTLD_NEXT, #name)
#define RETURN(name, fd, args)                                                 \
  do {                                                                         \
    LOAD(name);                                                                \
    __typeof__(next args) r = next args;                                       \
    int e = errno;                                                             \
    event(#name, fd, r, r < 0 ? e : 0, 0, 0);                                  \
    errno = e;                                                                 \
    return r;                                                                  \
  } while (0)
int connect(int fd, const struct sockaddr *a, socklen_t n) {
  LOAD(connect);
  int r = next(fd, a, n), e = errno;
  event("connect", fd, r, r < 0 ? e : 0, a, n);
  errno = e;
  return r;
}
int bind(int fd, const struct sockaddr *a, socklen_t n) {
  RETURN(bind, fd, (fd, a, n));
}
int listen(int fd, int n) {
  LOAD(listen);
  int r = next(fd, n), e = errno;
  event_arg("listen", fd, r, r < 0 ? e : 0, 0, 0, n);
  errno = e;
  return r;
}
int accept4(int fd, struct sockaddr *a, socklen_t *n, int flags) {
  LOAD(accept4);
  int r = next(fd, a, n, flags), e = errno;
  event_arg("accept4", r >= 0 ? r : fd, r, r < 0 ? e : 0, 0, 0, fd);
  errno = e;
  return r;
}
int accept(int fd, struct sockaddr *a, socklen_t *n) {
  LOAD(accept);
  int r = next(fd, a, n), e = errno;
  event_arg("accept", r >= 0 ? r : fd, r, r < 0 ? e : 0, 0, 0, fd);
  errno = e;
  return r;
}
int getsockopt(int fd, int level, int option, void *v, socklen_t *n) {
  LOAD(getsockopt);
  int r = next(fd, level, option, v, n), e = errno;
  if (level == SOL_SOCKET && option == SO_ERROR && r == 0 && *n == sizeof(int))
    event("SO_ERROR", fd, *(int *)v, 0, 0, 0);
  errno = e;
  return r;
}
int shutdown(int fd, int how) {
  LOAD(shutdown);
  int r = next(fd, how), e = errno;
  event_arg("shutdown", fd, r, r < 0 ? e : 0, 0, 0, how);
  errno = e;
  return r;
}
int close(int fd) {
  LOAD(close);
  int e = errno;
  event("close-enter", fd, 0, 0, 0, 0);
  errno = e;
  return next(fd);
}
ssize_t read(int fd, void *b, size_t n) { RETURN(read, fd, (fd, b, n)); }
ssize_t write(int fd, const void *b, size_t n) {
  RETURN(write, fd, (fd, b, n));
}
ssize_t readv(int fd, const struct iovec *v, int n) {
  RETURN(readv, fd, (fd, v, n));
}
ssize_t writev(int fd, const struct iovec *v, int n) {
  RETURN(writev, fd, (fd, v, n));
}
ssize_t recv(int fd, void *b, size_t n, int flags) {
  RETURN(recv, fd, (fd, b, n, flags));
}
ssize_t send(int fd, const void *b, size_t n, int flags) {
  RETURN(send, fd, (fd, b, n, flags));
}
ssize_t recvfrom(int fd, void *b, size_t n, int flags, struct sockaddr *a,
                 socklen_t *len) {
  RETURN(recvfrom, fd, (fd, b, n, flags, a, len));
}
ssize_t sendto(int fd, const void *b, size_t n, int flags,
               const struct sockaddr *a, socklen_t len) {
  RETURN(sendto, fd, (fd, b, n, flags, a, len));
}
ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
  RETURN(recvmsg, fd, (fd, msg, flags));
}
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
  RETURN(sendmsg, fd, (fd, msg, flags));
}
