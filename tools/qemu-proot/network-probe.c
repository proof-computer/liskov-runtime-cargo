#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ROUTE_MAX_RECORDS 128
#define ROUTE_MAX_BYTES (16 * 1024)

enum route_result {
    ROUTE_SELECTED = 0,
    ROUTE_UNSUPPORTED = 1,
    ROUTE_INVALID = 2,
    ROUTE_CANCELLED = 3,
    ROUTE_BOUNDED = 4,
};

struct fixture_route {
    uint32_t destination;
    uint8_t prefix_len;
    uint32_t gateway;
    int has_gateway;
    uint32_t metric;
    uint32_t interface_index;
};

static int gateway_acceptable(uint32_t gateway) {
    uint32_t first = (gateway >> 24) & 0xffu;
    if (gateway == 0 || gateway == 0xffffffffu) {
        return 0;
    }
    if (first == 127 || first >= 224) {
        return 0;
    }
    return 1;
}

/* Same rules as src/network_traversal/gateway.rs. Fixtures are in memory:
 * this probe does not read the host route table, scan a subnet, or take a
 * router credential. */
static enum route_result select_routes(
    const struct fixture_route *routes,
    size_t count,
    int cancelled,
    uint32_t *selected
) {
    size_t index;
    int saw_invalid = 0;
    int ambiguous = 0;
    int have_best = 0;
    struct fixture_route best;
    memset(&best, 0, sizeof(best));
    if (cancelled) {
        return ROUTE_CANCELLED;
    }
    if (count > ROUTE_MAX_RECORDS) {
        return ROUTE_BOUNDED;
    }
    for (index = 0; index < count; index += 1) {
        const struct fixture_route *route = &routes[index];
        if (route->destination != 0 || route->prefix_len != 0 || !route->has_gateway) {
            continue;
        }
        if (!gateway_acceptable(route->gateway)) {
            saw_invalid = 1;
            continue;
        }
        if (!have_best || route->metric < best.metric) {
            best = *route;
            have_best = 1;
            ambiguous = 0;
        } else if (route->metric == best.metric && route->gateway != best.gateway) {
            ambiguous = 1;
        } else if (route->metric == best.metric &&
                   route->gateway == best.gateway &&
                   route->interface_index < best.interface_index) {
            best = *route;
        }
    }
    if (ambiguous) {
        return ROUTE_UNSUPPORTED;
    }
    if (have_best) {
        *selected = best.gateway;
        return ROUTE_SELECTED;
    }
    return saw_invalid ? ROUTE_INVALID : ROUTE_UNSUPPORTED;
}

static int expect_route(
    const char *name,
    enum route_result got,
    enum route_result want,
    uint32_t selected,
    uint32_t want_gateway
) {
    if (got != want || (want == ROUTE_SELECTED && selected != want_gateway)) {
        fprintf(stderr, "route fixture %s failed\n", name);
        return -1;
    }
    return 0;
}

static int route_fixtures(void) {
    struct fixture_route on_link = {
        .destination = 0x0a010200u,
        .prefix_len = 24,
        .gateway = 0,
        .has_gateway = 0,
        .metric = 0,
        .interface_index = 1,
    };
    struct fixture_route defaults[3];
    struct fixture_route tie[2];
    struct fixture_route invalid;
    struct fixture_route too_many[ROUTE_MAX_RECORDS + 1];
    uint32_t selected = 0;
    enum route_result got;
    size_t index;

    /* `selected` is an output of select_routes. Read it only after that call
     * returns: argument evaluation order is unspecified. */
    got = select_routes(NULL, 0, 0, &selected);
    if (expect_route("missing", got, ROUTE_UNSUPPORTED, selected, 0) != 0) {
        return -1;
    }
    selected = 0xffffffffu;
    got = select_routes(&on_link, 1, 0, &selected);
    if (expect_route("on-link", got, ROUTE_UNSUPPORTED, 0, 0) != 0 ||
        selected == 0x0a010201u) {
        fprintf(stderr, "route fixture on-link invented a gateway\n");
        return -1;
    }
    memset(defaults, 0, sizeof(defaults));
    defaults[0] = on_link;
    defaults[1] = (struct fixture_route){
        .destination = 0,
        .prefix_len = 0,
        .gateway = 0xc0a80002u,
        .has_gateway = 1,
        .metric = 200,
        .interface_index = 2,
    };
    defaults[2] = (struct fixture_route){
        .destination = 0,
        .prefix_len = 0,
        .gateway = 0xc0a80001u,
        .has_gateway = 1,
        .metric = 100,
        .interface_index = 1,
    };
    selected = 0;
    got = select_routes(defaults, 3, 0, &selected);
    if (expect_route("multiple", got, ROUTE_SELECTED, selected, 0xc0a80001u) != 0) {
        return -1;
    }
    tie[0] = defaults[2];
    tie[1] = defaults[1];
    tie[1].metric = 100;
    got = select_routes(tie, 2, 0, &selected);
    if (expect_route("tie", got, ROUTE_UNSUPPORTED, 0, 0) != 0) {
        return -1;
    }
    invalid = defaults[2];
    invalid.gateway = 0;
    got = select_routes(&invalid, 1, 0, &selected);
    if (expect_route("invalid", got, ROUTE_INVALID, 0, 0) != 0) {
        return -1;
    }
    got = select_routes(defaults, 3, 1, &selected);
    if (expect_route("cancelled", got, ROUTE_CANCELLED, 0, 0) != 0) {
        return -1;
    }
    for (index = 0; index < ROUTE_MAX_RECORDS + 1; index += 1) {
        too_many[index] = defaults[2];
        too_many[index].metric = (uint32_t)index;
    }
    got = select_routes(too_many, ROUTE_MAX_RECORDS + 1, 0, &selected);
    if (expect_route("bounded-records", got, ROUTE_BOUNDED, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

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
    if (route_fixtures() != 0) {
        return fail("route fixtures");
    }

    printf("self-test passed: uid=0 cwd=/root low-port=denied "
           "af_inet=tcp-loopback af_netlink=%s getifaddrs=%s route-fixtures=ok\n",
           strcmp(argv[1], "netlink-eperm") == 0 ? "eperm" : "open",
           strcmp(argv[2], "shim-on") == 0 ? "loopback-only" : "host-visible");
    return 0;
}
