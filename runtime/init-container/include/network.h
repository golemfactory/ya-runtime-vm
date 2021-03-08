#ifndef _NETWORK_H
#define _NETWORK_H

#define MTU 65521

int net_create_lo(char *name);
int net_create_tap(char *name);

int net_if_up(const char *name, int up);
int net_if_mtu(const char *name, int mtu);
int net_if_addr(const char *name, const char *ip, const char *mask);
int net_if_addr6(const char *name, const char *ip6);
int net_if_hw_addr(const char *name, const char mac[6]);

int net_route(const char *ip, const char *via);
int net_route6(const char *name, const char *ip6, const char *via);

#endif // _NETWORK_H
