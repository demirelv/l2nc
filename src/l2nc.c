
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include<time.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>

#define PKT_CMD_DATA 2
#define PKT_CMD_ACK 3

#if !defined(TAILQ_FOREACH_SAFE)
#define TAILQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = TAILQ_FIRST((head));				\
		(var) && ((next) = TAILQ_NEXT((var), field), 1);	\
		(var) = (next))
#endif

struct header {
	struct ether_header ether;
	uint32_t cmd;
	uint32_t id;
	uint32_t eof;
	uint32_t seq;
	uint32_t len;
} __attribute__((packed));

struct packet {
	struct header header;
	uint8_t data[0];
} __attribute__((packed));

struct pkt_elem {
	TAILQ_ENTRY(pkt_elem) list;
	int seq;
	int id;
	time_t time;
	int retry;
	int length;
	int eof;
	uint8_t *data;
};

static TAILQ_HEAD(pkt_list, pkt_elem) pkt_list = TAILQ_HEAD_INITIALIZER(pkt_list);
static int dump_size = 1024 * 128;

static int create_raw_socket(const char *ifname, const unsigned short proto)
{
	int sockfd = -1;
	struct ifreq ifreq;
	struct sockaddr_ll sockaddr;

	sockfd = socket(PF_PACKET, SOCK_RAW, htons(proto));
	if (sockfd < 0) {
		perror("can not create packet socket");
		goto bail;
	}

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifreq) < 0) {
		goto bail;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_ifindex = ifreq.ifr_ifindex;
	sockaddr.sll_protocol = htons(proto);

	if (bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		goto bail;
	}

	return sockfd;

bail:
	if (sockfd > -1) {
		close(sockfd);
	}
	return -1;
}

static int l2_send(int sockfd, uint32_t cmd, uint32_t id, uint32_t seq, const uint8_t *dhost, const uint8_t *shost, const uint16_t proto, const uint8_t *buffer, const int size, int eof, int ms)
{
	struct packet *p = NULL;
	int s = size + sizeof(struct packet);
	int rc = -1;

	if (s > (int)(1500 + sizeof(struct ether_header))) {
		goto out;
	}

	if (s < (int)(46 + sizeof(struct ether_header))) {
		s = 50 + sizeof(struct ether_header);
	}

	p = calloc(1, s);
	if (p == NULL) {
		goto out;
	}

	memcpy(p->header.ether.ether_shost, shost, ETH_ALEN);
	memcpy(p->header.ether.ether_dhost, dhost, ETH_ALEN);
	p->header.ether.ether_type = htons(proto);
	p->header.cmd = htonl(cmd);
	p->header.seq = htonl(seq);
	p->header.id = htonl(id);
	p->header.eof = htonl(eof);
	p->header.len = htonl(size);

	if (size > 0)
		memcpy(p->data, buffer, size);

	if (ms)
		usleep(ms * 1000);
	rc = send(sockfd, p, s, MSG_NOSIGNAL);
	if (rc != s) {
		fprintf(stderr, "could not send %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x proto:%04x, rc:%d error '%s'\n",
			p->header.ether.ether_shost[0], p->header.ether.ether_shost[1], p->header.ether.ether_shost[2],
			p->header.ether.ether_shost[3], p->header.ether.ether_shost[4], p->header.ether.ether_shost[5],
			p->header.ether.ether_dhost[0], p->header.ether.ether_dhost[1], p->header.ether.ether_dhost[2],
			p->header.ether.ether_dhost[3], p->header.ether.ether_dhost[4], p->header.ether.ether_dhost[5],
			ntohs(p->header.ether.ether_type), rc, strerror(errno));
		rc = -1;
		goto out;
	}
	rc = size;
out:
	if (p != NULL) {
		free(p);
	}
	return rc;
}

static int read_dump_buf(uint8_t **buf, int size, int *eof)
{
	int i = 0;
	uint8_t *buffer = NULL;
	int len;

	if (dump_size <= 0) {
		*eof = 1;
		return 0;
	}

	len = dump_size > size ? size : dump_size;

	buffer = malloc(len);
	if (buffer == NULL)
		return -1;
	for (i = 0; i < len; i++) {
		buffer[i] = i % 2 ? 0xAA : 0x55;
	}
	*buf = buffer;
	dump_size -= len;
	if (dump_size <= 0) {
		*eof = 1;
	}
	return len;
}

static struct pkt_elem *add_packet(uint8_t *buf, int size, int id, int seq, int eof)
{
	struct pkt_elem *p = NULL;

	if (buf == NULL || size == 0)
		return NULL;

	p = calloc(1, sizeof(struct pkt_elem));
	if (p == NULL)
		return NULL;

	p->data = buf;
	p->seq = seq;
	p->id = id;
	p->length = size;
	p->eof = eof;
	p->time = time(NULL);
	p->retry = 0;

	TAILQ_INSERT_TAIL(&pkt_list, p, list);

	return p;
}

static void remove_packet(struct pkt_elem *p)
{
	TAILQ_REMOVE(&pkt_list, p, list);
	if (p->data != NULL)
		free(p->data);
	free(p);
}

static struct pkt_elem *get_packet(int seq)
{
	struct pkt_elem *p = NULL;

	TAILQ_FOREACH(p, &pkt_list, list) {
		if (p->seq == seq)
			return p;
	}

	return NULL;
}

static struct pkt_elem *get_packet_id(int id)
{
	struct pkt_elem *p = NULL;

	TAILQ_FOREACH(p, &pkt_list, list) {
		if (p->id == id)
			return p;
	}

	return NULL;
}

void usage(void)
{
	printf("l2nc\n");
	exit(0);
}

void print_packet(struct packet *p)
{
	int i;

	printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x proto %04x, len:%d, id:%d, seq:%d, eof:%d\n",
			p->header.ether.ether_shost[0],
			p->header.ether.ether_shost[1],
			p->header.ether.ether_shost[2],
			p->header.ether.ether_shost[3],
			p->header.ether.ether_shost[4],
			p->header.ether.ether_shost[5],
			p->header.ether.ether_dhost[0],
			p->header.ether.ether_dhost[1],
			p->header.ether.ether_dhost[2],
			p->header.ether.ether_dhost[3],
			p->header.ether.ether_dhost[4],
			p->header.ether.ether_dhost[5], ntohs(p->header.ether.ether_type), p->header.len,
			p->header.id, p->header.seq, p->header.eof);
	for (i = 0; i < (int)p->header.len; i++) {
		printf("%02x", p->data[i]);
		if (i != 0 && i % 16 == 0)
			printf(" ");
		if (i != 0 && i % 64 == 0)
			printf("\n");
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	int sockfd = -1;
	char *ifname = "eth0";
	uint16_t proto = 0x7070;
	int serverflag = 0;
	int timeout = 30;
	int wait = 0;
	int buffer_size = 1024;
	uint8_t dhost[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t ihost[ETH_ALEN];
	struct pollfd fds;
	struct ifreq ifreq;
	uint8_t *buf = NULL;
	int rc = 0;
	char ch;
	int eof = 0;
	int seq = 0;
	int id = 0;
	struct pkt_elem *p = NULL;
	struct pkt_elem *n = NULL;
	int i = 0;
	int waitack = 0;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv,
		"i:p:ld:t:w:b:s:ha"))
		!= -1) {
		switch (ch) {
		case 'i':
			ifname = optarg;
			break;
		case 'p':
			proto = strtol(optarg, NULL, 16);
			break;
		case 'l':
			serverflag = 1;
			break;
		case 'a':
			waitack = 1;
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 's':
			dump_size = atoi(optarg);
			break;
		case 'w':
			wait = atoi(optarg);
			break;
		case 'b':
			buffer_size = atoi(optarg);
			break;
		case 'd':
			if (sscanf(optarg, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
						&dhost[0], &dhost[1], &dhost[2], &dhost[3],
						&dhost[4], &dhost[5]) < 6) {
					fprintf(stderr, "could not parse %s\n", optarg);
				}
				break;
		case 'h':
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	sockfd = create_raw_socket(ifname, proto);
	if (sockfd < 0)
		goto out;

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0)
		perror("SIOCGIFHWADDR");

	memcpy(ihost, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

	for (;;) {
		int tm = timeout;

		fds.fd = sockfd;
		fds.revents = 0;
		fds.events = 0;
		fds.events |= POLLIN;
		fds.events |= POLLOUT;

		if (!serverflag) {
			int count = 0;

			TAILQ_FOREACH(p, &pkt_list, list) {
				time_t ct = time(NULL);

				count++;
				if (p->time <= ct) {
					if (p->retry > 30) {
						fprintf(stderr, "Could not recive ack for %d\n", p->id);
						goto out;
					}
					p->time = ct + timeout;
					p->seq = seq++;
					p->retry++;
					fprintf(stderr, "resending %d, retry=%d seq=%d\n", p->id, p->retry, p->seq);
					rc = l2_send(sockfd, PKT_CMD_DATA, p->id, p->seq, dhost, ihost, proto, p->data, p->length, p->eof, wait);
					if (rc < 0)
						goto out;
				}
				if (tm > p->time - ct) {
					tm = p->time - ct;
				}
			}
			if (eof && count == 0) {
				fprintf(stderr, "file transfer complete!\n");
				break;
			}
			for (i = count; eof == 0 && i < (waitack ? 32 : 1); i++) {
				rc = read_dump_buf(&buf, buffer_size, &eof);
				if (rc < 0)
					goto out;

				p = add_packet(buf, rc, id++, seq++, eof);
				if (p == NULL)
					goto out;

				rc = l2_send(sockfd, PKT_CMD_DATA, p->id, p->seq, dhost, ihost, proto, p->data, p->length, eof, wait);
				if (rc < 0)
					goto out;

				if (eof)
					break;
			}
		}

		rc = poll(&fds, 1, tm * 1000);
		if (rc < 0) {
			if (errno == EINTR)
				continue;

			perror("poll failed");
			break;
		}
		if (rc == 0)
			continue;

		if (fds.revents & POLLERR) {
			fprintf(stderr, "something going wrong!\n");
			break;
		}
		if ((fds.revents & POLLOUT) != 0) {
			if (!waitack && serverflag) {
				TAILQ_FOREACH_SAFE(p, &pkt_list, list, n) {
					remove_packet(p);
				}
			}
		}
		if ((fds.revents & POLLIN) != 0) {
			uint8_t data[1800];
			struct packet *packet = (struct packet *)data;

			rc = recv(fds.fd, data,
						sizeof(data), MSG_DONTWAIT);
			if (rc < 0)
				goto out;

			packet->header.ether.ether_type = ntohs(packet->header.ether.ether_type);
			packet->header.cmd = ntohl(packet->header.cmd);
			packet->header.id = ntohl(packet->header.id);
			packet->header.seq = ntohl(packet->header.seq);
			packet->header.eof = ntohl(packet->header.eof);
			packet->header.len = ntohl(packet->header.len);

			if (!serverflag && packet->header.cmd == PKT_CMD_ACK) {
				p = get_packet(packet->header.seq);
				if (p != NULL)
					remove_packet(p);

			} else if (serverflag && packet->header.cmd == PKT_CMD_DATA) {
				if (waitack) {
					rc = l2_send(sockfd, PKT_CMD_ACK, packet->header.id, packet->header.seq, packet->header.ether.ether_shost, ihost, proto, NULL, 0, 0, 0);
					if (rc < 0)
						goto out;
				}

				if ((int)(packet->header.id) == id) {
					id++;
					print_packet(packet);
					if (packet->header.eof)
						eof = 1;
					do {
						p = get_packet_id(id);
						if (p == NULL)
							break;
						id++;
						print_packet((struct packet *)p->data);
						if (p->eof)
							eof = 1;
						remove_packet(p);
					} while (1);
				} else if ((int)(packet->header.id) > id) {
					uint8_t *tmpbuf = NULL;

					tmpbuf = calloc(1, rc);
					if (tmpbuf == NULL)
						goto out;

					memcpy(tmpbuf, data, rc);
					add_packet(tmpbuf, rc, packet->header.id, packet->header.seq, packet->header.eof);
				}
				if (eof)
					break;
			}
		}
	}
out:
	TAILQ_FOREACH_SAFE(p, &pkt_list, list, n) {
		remove_packet(p);
	}
	if (sockfd > -1)
		close(sockfd);

	return 0;
}
