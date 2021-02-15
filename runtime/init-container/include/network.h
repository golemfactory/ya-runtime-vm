#ifndef _NETWORK_H
#define _NETWORK_H

int net_create_lo(char *name);
int net_create_tun(char *name);

int net_if_up(char *name, int up);
int net_if_addr(char *name, char *ip, char *mask);
int net_if_addr6(char *name, char *ip6);

int net_route(char *ip, char *via);
int net_route6(char *name, char *ip6, char *via);

#endif // _NETWORK_H
