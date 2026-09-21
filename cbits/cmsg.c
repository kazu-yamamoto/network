#include "HsNet.h"
#include <string.h>

#ifdef _WIN32

LPWSACMSGHDR cmsg_firsthdr(LPWSAMSG mhdr) {
  return (WSA_CMSG_FIRSTHDR(mhdr));
}

LPWSACMSGHDR cmsg_nxthdr(LPWSAMSG mhdr, LPWSACMSGHDR cmsg) {
  return (WSA_CMSG_NXTHDR(mhdr, cmsg));
}

unsigned char *cmsg_data(LPWSACMSGHDR cmsg) {
  return (WSA_CMSG_DATA(cmsg));
}

unsigned int cmsg_space(unsigned int l) {
  return (WSA_CMSG_SPACE(l));
}

unsigned int cmsg_len(unsigned int l) {
  return (WSA_CMSG_LEN(l));
}

/* GUIDs to look up WSASendMsg/WSARecvMsg.  Winsock does not export them
   as ordinary symbols; they have to be fetched from a live socket.  The
   caching lives in Haskell (Network.Socket.Win32.Load) so that the call
   itself can be issued asynchronously from there.  */
static GUID WSARecvMsgGUID = WSAID_WSARECVMSG;
static GUID WSASendMsgGUID = WSAID_WSASENDMSG;

LPFN_WSASENDMSG loadWSASendMsg (SOCKET s) {
  LPFN_WSASENDMSG fn = NULL;
  DWORD len;

  if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
               &WSASendMsgGUID, sizeof(WSASendMsgGUID), &fn, sizeof(fn),
               &len, NULL, NULL) != 0)
    return NULL;

  return fn;
}

LPFN_WSARECVMSG loadWSARecvMsg (SOCKET s) {
  LPFN_WSARECVMSG fn = NULL;
  DWORD len;

  if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
               &WSARecvMsgGUID, sizeof(WSARecvMsgGUID), &fn, sizeof(fn),
               &len, NULL, NULL) != 0)
    return NULL;

  return fn;
}

#else
struct cmsghdr *cmsg_firsthdr(struct msghdr *mhdr) {
  return (CMSG_FIRSTHDR(mhdr));
}

struct cmsghdr *cmsg_nxthdr(struct msghdr *mhdr, struct cmsghdr *cmsg) {
  return (CMSG_NXTHDR(mhdr, cmsg));
}

unsigned char *cmsg_data(struct cmsghdr *cmsg) {
  return (CMSG_DATA(cmsg));
}

size_t cmsg_space(size_t l) {
  return (CMSG_SPACE(l));
}

size_t cmsg_len(size_t l) {
  return (CMSG_LEN(l));
}
#endif /* _WIN32 */
