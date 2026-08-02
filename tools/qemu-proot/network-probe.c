#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "network probe failed: %s\n", message);
    return 1;
}

static int probe_loopback_tcp(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener == -1) {
        return -1;
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) == -1 ||
        listen(listener, 1) == -1) {
        close(listener);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &length) == -1) {
        close(listener);
        return -1;
    }
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client == -1 ||
        connect(client, (struct sockaddr *)&address, sizeof(address)) == -1) {
        if (client != -1) {
            close(client);
        }
        close(listener);
        return -1;
    }
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (accepted == -1) {
        close(client);
        close(listener);
        return -1;
    }
    close(accepted);
    close(client);
    close(listener);
    return 0;
}

static int probe_privileged_port_denied(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener == -1) {
        return -1;
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(22),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    errno = 0;
    int result = bind(listener, (struct sockaddr *)&address, sizeof(address));
    int bind_errno = errno;
    close(listener);
    return result == -1 && bind_errno == EACCES ? 0 : 1;
}

static int interface_shape(void) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) == -1) {
        return -1;
    }
    bool saw_loopback = false;
    bool saw_other = false;
    for (struct ifaddrs *item = interfaces; item != NULL; item = item->ifa_next) {
        if (item->ifa_name == NULL) {
            continue;
        }
        if (strcmp(item->ifa_name, "lo") == 0) {
            saw_loopback = true;
        } else {
            saw_other = true;
        }
    }
    freeifaddrs(interfaces);
    if (!saw_loopback) {
        return 2;
    }
    return saw_other ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 3 ||
        (strcmp(argv[1], "netlink-open") != 0 &&
         strcmp(argv[1], "netlink-eperm") != 0) ||
        (strcmp(argv[2], "shim-on") != 0 && strcmp(argv[2], "shim-off") != 0)) {
        return fail("expected netlink-open|netlink-eperm and shim-on|shim-off");
    }
    if (probe_loopback_tcp() == -1) {
        return fail("AF_INET loopback TCP is unavailable");
    }
    if (probe_privileged_port_denied() != 0) {
        return fail("the unprivileged host UID could bind TCP port 22");
    }
    if (geteuid() != 0) {
        return fail("PRoot did not expose guest uid 0");
    }
    char working_directory[64];
    if (getcwd(working_directory, sizeof(working_directory)) == NULL ||
        strcmp(working_directory, "/root") != 0) {
        return fail("guest working directory is not /root");
    }
    const char *home = getenv("HOME");
    if (home == NULL || strcmp(home, "/root") != 0) {
        return fail("guest HOME is not /root");
    }

    errno = 0;
    int netlink = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (strcmp(argv[1], "netlink-eperm") == 0) {
        if (netlink != -1 || errno != EPERM) {
            if (netlink != -1) {
                close(netlink);
            }
            return fail("AF_NETLINK did not fail with EPERM");
        }
    } else if (netlink == -1) {
        return fail("AF_NETLINK is unavailable in processor-like mode");
    }
    if (netlink != -1) {
        close(netlink);
    }

    int interfaces = interface_shape();
    if (interfaces == -1) {
        return fail("getifaddrs failed");
    }
    if (strcmp(argv[2], "shim-on") == 0 && interfaces != 0) {
        return fail("getifaddrs shim did not return only loopback");
    }
    if (strcmp(argv[2], "shim-off") == 0 && interfaces != 1) {
        return fail("getifaddrs without the shim did not expose a non-loopback interface");
    }

    printf("self-test passed: uid=0 cwd=/root low-port=denied "
           "af_inet=tcp-loopback af_netlink=%s getifaddrs=%s\n",
           strcmp(argv[1], "netlink-eperm") == 0 ? "eperm" : "open",
           strcmp(argv[2], "shim-on") == 0 ? "loopback-only" : "host-visible");
    return 0;
}
