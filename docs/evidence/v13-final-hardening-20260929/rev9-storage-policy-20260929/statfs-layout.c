#include <sys/mount.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(void) {
  struct statfs s;
  int fd = open("/Users/michael", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0 || fstatfs(fd, &s) != 0) return 1;
  printf("size=%zu flagsOffset=%zu formatOffset=%zu availableOffset=%zu type=%s flags=%u blocksize=%u available=%llu\n",sizeof(s),offsetof(struct statfs,f_flags),offsetof(struct statfs,f_fstypename),offsetof(struct statfs,f_bavail),s.f_fstypename,s.f_flags,s.f_bsize,(unsigned long long)s.f_bavail);
  close(fd);
  return 0;
}
