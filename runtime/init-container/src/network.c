#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "network.h"

static int alias_counter = 0;

struct ifreq6_stub {
    struct in6_addr addr;
    uint32_t prefixlen;
    int32_t ifindex;
};

int parse_prefix_len(const char *ip) {
    char *cp;
    if ((cp = strchr(ip, '/'))) {
        return atol(cp + 1);
    }
    return -1;
}

int net_if_alias(struct ifreq *ifr, const char *name) {
    const int suffix_len = 5;
    if (strlen(name) >= sizeof(ifr->ifr_name) - suffix_len) {
        return -1;
    }
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name) - 1,
            "%s:%d", name, ++alias_counter);
    return 0;
}

int net_create_lo(char *name) {
    struct ifreq ifr;
    int fd, ret;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_LOOPBACK | IFF_UP;

    if ((ret = ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_create_tun(char *name) {
    struct ifreq ifr;
    int fd, ret;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return -EALREADY;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_UP;

    if (*name) {
        strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    }

    if ((ret = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
        goto err;
    }

    strcpy(name, ifr.ifr_name);
    return fd;
err:
    close(fd);
    return ret;
}

int net_if_up(const char *name, int up) {
    struct ifreq ifr;
    int fd, ret;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    if (up) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if ((ret = ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_if_mtu(const char *name, int mtu) {
    struct ifreq ifr;
    int fd, ret;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    ifr.ifr_addr.sa_family = AF_INET;
    ifr.ifr_mtu = mtu;
    if ((ret = ioctl(fd, SIOCSIFMTU, &ifr)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_if_addr(const char *name, const char *ip, const char *mask) {
    struct ifreq ifr;
    int fd, ret;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    if ((ret = ioctl(fd, SIOCGIFADDR, &ifr)) == 0) {
        if ((ret = net_if_alias(&ifr, name)) < 0) {
            goto end;
        }
    }

    struct sockaddr_in* sa = (struct sockaddr_in*) &ifr.ifr_addr;
    sa->sin_family = AF_INET;

    if ((ret = inet_pton(AF_INET, ip, &sa->sin_addr)) < 0) {
        goto end;
    }
    if ((ret = ioctl(fd, SIOCSIFADDR, &ifr)) < 0) {
        goto end;
    }
    if ((ret = inet_pton(AF_INET, mask, &sa->sin_addr)) < 0) {
        goto end;
    }
    if ((ret = ioctl(fd, SIOCSIFNETMASK, &ifr)) < 0) {
        goto end;
    }

    ifr.ifr_flags = IFF_UP;
    if ((ret = ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_if_addr6(const char *name, const char *ip6) {
    struct ifreq ifr;
    struct ifreq6_stub ifr6;
    int fd, ret, pl;

    if ((fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    memset(&ifr6, 0, sizeof(ifr6));

    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if ((ret = ioctl(fd, SIOGIFINDEX, &ifr)) < 0) {
        goto end;
    }

    if ((ret = ioctl(fd, SIOCGIFADDR, &ifr)) == 0) {
        if ((ret = net_if_alias(&ifr, name)) < 0) {
            goto end;
        }
    }

    if ((pl = parse_prefix_len(ip6)) < 0) {
        pl = 128;
    }

    ifr6.ifindex = ifr.ifr_ifindex;
    ifr6.prefixlen = pl;

    if ((ret = inet_pton(AF_INET6, ip6, (void *) &ifr6.addr)) < 0) {
        goto end;
    }
    if ((ret = ioctl(fd, SIOCSIFADDR, &ifr6)) < 0) {
        goto end;
    }

    ifr.ifr_flags |= IFF_UP;
    if ((ret = ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_route(const char *ip, const char *via) {
    struct rtentry rt;
    struct sockaddr_in *addr;
    int fd, ret = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return -1;
    }

    memset(&rt, 0, sizeof(rt));

    addr = (struct sockaddr_in*) &rt.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(ip);

    rt.rt_flags |= RTF_UP | RTF_HOST;
    while (!ioctl(fd, SIOCDELRT, &rt));
    rt.rt_flags |= RTF_GATEWAY;

    addr = (struct sockaddr_in *) &rt.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(via);

    if ((ret = ioctl(fd, SIOCADDRT, (void *) &rt)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}

int net_route6(const char *name, const char *ip6, const char *via) {
    struct ifreq ifr;
    struct in6_rtmsg rt;
    int fd, pl, ret = 0;

    if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if ((ret = ioctl(fd, SIOGIFINDEX, &ifr)) < 0) {
        goto end;
    }

    memset(&rt, 0, sizeof(rt));

    if ((ret = inet_pton(AF_INET6, ip6, (void *) &(rt.rtmsg_dst))) < 0) {
        goto end;
    }
    if ((pl = parse_prefix_len(ip6)) < 0) {
        pl = 128;
    }

    rt.rtmsg_flags |= RTF_UP | RTF_HOST;
    while (!ioctl(fd, SIOCDELRT, &rt));
    rt.rtmsg_flags |= RTF_GATEWAY;

    rt.rtmsg_ifindex = ifr.ifr_ifindex;
    rt.rtmsg_dst_len = pl;
    rt.rtmsg_metric = 101;

    if ((ret = inet_pton(AF_INET6, via, (void *) &(rt.rtmsg_gateway))) < 0) {
        goto end;
    }

    if ((ret = ioctl(fd, SIOCADDRT, (void *) &rt)) < 0) {
        goto end;
    }
end:
    close(fd);
    return ret;
}
