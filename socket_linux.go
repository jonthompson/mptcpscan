//go:build linux && cgo

package main

/*
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static int open_raw(uint32_t source, uint16_t port, int rx, int size, int *actual) {
 int fd=socket(AF_INET,SOCK_RAW|SOCK_CLOEXEC,rx?IPPROTO_TCP:IPPROTO_RAW);
 if(fd<0) return -errno;
 int opt=rx?SO_RCVBUF:SO_SNDBUF;
 if(setsockopt(fd,SOL_SOCKET,opt,&size,sizeof(size))<0) { int e=errno; close(fd); return -e; }
 socklen_t olen=sizeof(*actual); getsockopt(fd,SOL_SOCKET,opt,actual,&olen);
 if(rx) {
  int one=1;
  if(setsockopt(fd,SOL_SOCKET,SO_RXQ_OVFL,&one,sizeof(one))<0) {int e=errno;close(fd);return -e;}
  // Raw IPv4 sockets present the IP header at offset zero. Only our two ports.
  struct sock_filter code[]={
   BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,source,0,6),
   BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,0),
   BPF_STMT(BPF_LD|BPF_H|BPF_IND,2),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,port,1,0),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,port+1,0,2),
   BPF_STMT(BPF_RET|BPF_K,256),
   BPF_STMT(BPF_RET|BPF_K,0),
   BPF_STMT(BPF_RET|BPF_K,0)
  };
  struct sock_fprog prog={sizeof(code)/sizeof(code[0]),code};
  if(setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog))<0) { int e=errno;close(fd);return -e; }
 }
 return fd;
}

static int send_batch(int fd, unsigned char *data, int n) {
 struct mmsghdr m[64]={0}; struct iovec v[64]; struct sockaddr_in a[64]={0};
 for(int i=0;i<n;i++) {
  unsigned char *p=data+i*64;
  a[i].sin_family=AF_INET; memcpy(&a[i].sin_addr,p+16,4);
  v[i].iov_base=p; v[i].iov_len=((unsigned)p[2]<<8)|p[3];
  m[i].msg_hdr.msg_name=&a[i]; m[i].msg_hdr.msg_namelen=sizeof(a[i]);
  m[i].msg_hdr.msg_iov=&v[i]; m[i].msg_hdr.msg_iovlen=1;
 }
 int done=0;
 while(done<n) { int r=sendmmsg(fd,m+done,n-done,MSG_DONTWAIT);
  if(r<0) {if(errno==EINTR)continue;return done?done:-errno;} done+=r; }
 return done;
}

static int recv_batch(int fd, unsigned char *data, uint32_t *lengths, uint32_t *drops) {
 struct pollfd p={fd,POLLIN,0}; int ready=poll(&p,1,100);
 if(ready<0) return errno==EINTR?0:-errno;
 if(!ready) return 0;
 struct mmsghdr m[64]={0}; struct iovec v[64];
 union {struct cmsghdr align; unsigned char data[CMSG_SPACE(sizeof(uint32_t))];} ctrl[64];
 for(int i=0;i<64;i++) {
  v[i].iov_base=data+i*256; v[i].iov_len=256;
  m[i].msg_hdr.msg_iov=&v[i]; m[i].msg_hdr.msg_iovlen=1;
  m[i].msg_hdr.msg_control=ctrl[i].data; m[i].msg_hdr.msg_controllen=sizeof(ctrl[i].data);
 }
 int n=recvmmsg(fd,m,64,MSG_DONTWAIT,0);
 if(n<0) return (errno==EAGAIN||errno==EINTR)?0:-errno;
 for(int i=0;i<n;i++) {
  lengths[i]=(m[i].msg_hdr.msg_flags&MSG_TRUNC)?0:m[i].msg_len;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&m[i].msg_hdr);c;c=CMSG_NXTHDR(&m[i].msg_hdr,c))
   if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SO_RXQ_OVFL) memcpy(drops,CMSG_DATA(c),4);
 }
 return n;
}
*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
)

func openSocket(src uint32, port uint16, rx bool, size int) (int, int, error) {
	var actual C.int
	receive := 0
	if rx {
		receive = 1
	}
	fd := int(C.open_raw(C.uint32_t(src), C.uint16_t(port), C.int(receive), C.int(size), &actual))
	if fd < 0 {
		return 0, 0, fmt.Errorf("raw socket: %w", syscall.Errno(-fd))
	}
	return fd, int(actual), nil
}
func sendBatch(fd int, b []byte, n int) (int, error) {
	r := int(C.send_batch(C.int(fd), (*C.uchar)(unsafe.Pointer(&b[0])), C.int(n)))
	if r < 0 {
		return 0, syscall.Errno(-r)
	}
	return r, nil
}
func receiveBatch(fd int, b []byte, l *[64]uint32, drops *uint32) (int, error) {
	r := int(C.recv_batch(C.int(fd), (*C.uchar)(unsafe.Pointer(&b[0])), (*C.uint32_t)(unsafe.Pointer(&l[0])), (*C.uint32_t)(unsafe.Pointer(drops))))
	if r < 0 {
		return 0, syscall.Errno(-r)
	}
	return r, nil
}
