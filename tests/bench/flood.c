/* Private-veth ingress generator, not a physical-NIC line-rate benchmark. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 4
#define BATCH 64
struct worker { int cpu, id, extensions, error; uint64_t frames, calls, retries; };
static pthread_barrier_t ready;
static uint64_t deadline;

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static void *generate(void *arg) {
    struct worker *w = arg;
    cpu_set_t cpu;
    CPU_ZERO(&cpu); CPU_SET(w->cpu, &cpu);
    int error = pthread_setaffinity_np(pthread_self(), sizeof(cpu), &cpu);
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll link = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL)};
    link.sll_ifindex = if_nametoindex("players");
    if (!error && (fd < 0 || !link.sll_ifindex || bind(fd, (void *)&link, sizeof(link)))) error = errno;
    struct timeval timeout = {.tv_sec = 1};
    if (!error && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) error = errno;
    unsigned char packet[126] = {0};
    struct ifreq request = {0};
    strcpy(request.ifr_name, "eth0");
    if (!error && ioctl(fd, SIOCGIFHWADDR, &request)) error = errno;
    if (!error) memcpy(packet, request.ifr_hwaddr.sa_data, 6);
    strcpy(request.ifr_name, "players");
    if (!error && ioctl(fd, SIOCGIFHWADDR, &request)) error = errno;
    if (!error) memcpy(packet + 6, request.ifr_hwaddr.sa_data, 6);
    packet[12] = 0x86; packet[13] = 0xdd;
    packet[14] = 0x60; packet[20] = w->extensions ? 60 : 17; packet[21] = 64;
    inet_pton(AF_INET6, "fd00:bbbb::1", packet + 22);
    packet[37] = w->id + 1;
    inet_pton(AF_INET6, "fd00::1", packet + 38);
    for (int i = 0; i < w->extensions; i++) packet[54 + 8*i] = i == w->extensions-1 ? 17 : 60;
    size_t offset = 54 + 8*w->extensions;
    uint16_t port = htons(40000); memcpy(packet + offset, &port, 2);
    port = htons(60000 + w->id); memcpy(packet + offset + 2, &port, 2);
    size_t length = offset + 8;
    struct iovec vectors[BATCH];
    struct mmsghdr messages[BATCH] = {0};
    for (int i = 0; i < BATCH; i++) {
        vectors[i] = (struct iovec){.iov_base = packet, .iov_len = length};
        messages[i].msg_hdr.msg_iov = &vectors[i]; messages[i].msg_hdr.msg_iovlen = 1;
    }
    w->error = error;
    pthread_barrier_wait(&ready);
    if (!error) while (now_ns() < deadline) {
        int n = sendmmsg(fd, messages, BATCH, 0);
        w->calls++;
        if (n > 0) { w->frames += n; continue; }
        if (errno == EINTR || errno == EAGAIN || errno == ENOBUFS) { w->retries++; sched_yield(); continue; }
        w->error = errno; break;
    }
    if (fd >= 0) close(fd);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: flood <seconds:1-600> <extensions:0|8>\n"); return 1; }
    char *end;
    long seconds = strtol(argv[1], &end, 10);
    if (*end || seconds < 1 || seconds > 600) return 1;
    long extensions = strtol(argv[2], &end, 10);
    if (*end || (extensions != 0 && extensions != 8)) return 1;
    struct stat self, host;
    if (stat("/proc/self/ns/net", &self) || stat("/proc/1/ns/net", &host) ||
        (self.st_dev == host.st_dev && self.st_ino == host.st_ino)) {
        fprintf(stderr, "refusing flood outside a private network namespace\n"); return 1;
    }
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) { perror("affinity"); return 1; }
    struct worker workers[WORKERS] = {0};
    int n = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && n < WORKERS; cpu++) if (CPU_ISSET(cpu, &allowed)) {
        workers[n] = (struct worker){.id=n, .cpu=cpu, .extensions=extensions}; n++;
    }
    if (n != WORKERS) { fprintf(stderr, "requires four allowed CPUs\n"); return 1; }
    pthread_t threads[WORKERS];
    if (pthread_barrier_init(&ready, NULL, WORKERS+1)) return 1;
    for (int i = 0; i < WORKERS; i++) if (pthread_create(&threads[i], NULL, generate, &workers[i])) return 1;
    uint64_t start = now_ns(); deadline = start + seconds*1000000000ULL;
    pthread_barrier_wait(&ready);
    uint64_t frames=0, calls=0, retries=0;
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(threads[i], NULL);
        if (workers[i].error) { fprintf(stderr, "generator: %s\n", strerror(workers[i].error)); return 1; }
        frames += workers[i].frames; calls += workers[i].calls; retries += workers[i].retries;
    }
    double elapsed = (now_ns()-start)/1e9;
    printf("{\"frames\":%llu,\"seconds\":%.6f,\"pps\":%.0f,\"send_calls\":%llu,\"backpressure\":%llu,\"frame_bytes\":%ld,\"cpus\":[%d,%d,%d,%d]}\n",
        (unsigned long long)frames, elapsed, frames/elapsed, (unsigned long long)calls,
        (unsigned long long)retries, 62+8*extensions, workers[0].cpu, workers[1].cpu, workers[2].cpu, workers[3].cpu);
    pthread_barrier_destroy(&ready);
    return 0;
}
