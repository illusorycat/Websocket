/*
*   这是一个单线程上实现百万连接的reactor模型
*	实现的服务器为傻瓜式一问一答模式
* 
*	在本模型中，一个ntyevent只能绑定一个回调函数，所以当一个fd处理读写时，需要多次开关对应EPOLL事件监测
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


#define BUFFER_LENGTH		4095
#define MAX_EPOLL_EVENTS	1024
#define SERVER_PORT			9999
#define PORT_COUNT			1

#define GUID	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

enum {
	WS_HANDSHARK = 0,
	WS_TRANMISSION = 1,
	WS_END = 2,
};

typedef struct _ws_ophdr {
	unsigned char	opcode : 4,
		rsv3 : 1,
		rsv2 : 1,
		rsv1 : 1,
		fin : 1;
	unsigned char payload_length : 7,
		mask : 1;
	char mask_key[4];
}ws_ophdr;

typedef struct _ws_head_126 {
	unsigned short payload_length;
	char mask_key[4];
}ws_head_126;

typedef struct _ws_head_127 {
	unsigned long long payload_length;
	char mask_key[4];
}ws_head_127;



typedef int NCALLBACK(int, int, void*);  //fd, events, arg=reactor

struct ntyevent {
	int fd;
	int events;
	void* arg;
	int (*callback)(int fd, int events, void* arg);

	int status; //标注该ntyevent是否已经被监测
	char buffer[BUFFER_LENGTH+1]; //缓冲区
	int length;  //缓冲区内数据长度
	long last_active;

	int status_machine;  //状态机
};

struct eventblock {
	struct eventblock* next;  //指向下一个eventblock
	struct ntyevent* events; //events数组，长度为 MAX_EPOLL_EVENTS
};

struct ntyreactor {
	int epfd;  
	int blkcnt;  //counts of eventblock
	struct eventblock* evblk;  //
};

int recv_cb(int fd, int events, void* arg);  //连接fd，事件events，关联的reactor
int send_cb(int fd, int events, void* arg);
int accept_cb(int fd, int events, void* arg);
struct ntyevent* ntyreactor_idx(struct ntyreactor* reactor, int sockfd);

void nty_event_set(struct ntyevent* ev, int fd, NCALLBACK *callback, void* arg)
{
	ev->fd = fd;
	ev->callback = callback;
	ev->arg = arg;
	ev->events = 0;
	ev->status = 0;
	ev->last_active = time(NULL);

	return;
}

int nty_event_add(int epfd, int events, struct ntyevent* ev)
{
	struct epoll_event ep_ev = { 0,{0} };
	ep_ev.data.ptr = ev;
	ep_ev.events = ev->events = events;

	int op;
	if (ev->status == 1)
	{
		op = EPOLL_CTL_MOD;
	}
	else
	{
		op = EPOLL_CTL_ADD;
		ev->status = 1;
	}

	if (epoll_ctl(epfd, op, ev->fd, &ep_ev) < 0)
	{
		printf("event add failed [fd=%d], events[%d]\n", ev->fd, events);
		return -1;
	}
	return 0;
}

int nty_event_del(int epfd, struct ntyevent* ev)
{
	struct epoll_event  ep_ev = { 0,{0} };

	if (ev->status != 1)
	{
		return -1;
	}
	ep_ev.data.ptr = ev;
	ev->status = 0;
	epoll_ctl(epfd, EPOLL_CTL_DEL, ev->fd, &ep_ev);

	return 0;
}

int base64_encode(char* in_str, int in_len, char* out_str) {
	BIO* b64, * bio;
	BUF_MEM* bptr = NULL;
	size_t size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, in_str, in_len);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	memcpy(out_str, bptr->data, bptr->length);
	out_str[bptr->length - 1] = '\0';
	size = bptr->length;

	BIO_free_all(bio);
	return size;
}

int readline(char* allbuf, int idx, char* linebuf)
{
	int len = strlen(allbuf);

	for (; idx < len; ++idx)
	{
		if (allbuf[idx] == '\r' && allbuf[idx + 1] == '\n')
		{
			*linebuf = '\0';
			return idx + 2;
		}
		else
		{
			*(linebuf++) = allbuf[idx];
		}
	}

	return -1;
}

//19: length of "Sec-WebSocket-Key: "
#define WEBSOCK_KEY_LENGTH 19

int handshark(struct ntyevent* ev)
{
	char linebuf[1024] = { 0 };
	int idx = 0;
	char sec_data[128] = { 0 }; //用于存储Sec-WebSocket-Key计算Sec-WebSocket-Accept的计算中间值
	char sec_accept[32] = { 0 };  //存储Sec-WebSocket-Accept

	do {
		memset(linebuf, 0, 1024);
		idx = readline(ev->buffer, idx, linebuf);

		if (strstr(linebuf, "Sec-WebSocket-Key"))
		{
			strcat(linebuf, GUID);
			SHA1(linebuf + WEBSOCK_KEY_LENGTH, strlen(linebuf + WEBSOCK_KEY_LENGTH), sec_data);
			base64_encode(sec_data, strlen(sec_data), sec_accept);

			memset(ev->buffer, 0, BUFFER_LENGTH);

			ev->length = sprintf(ev->buffer, "HTTP/1.1 101 Switching Protocols\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Accept: %s\r\n\r\n", sec_accept);

			printf("ws response : %s\n", ev->buffer);

			break;
		}
	} while (idx != -1 && (ev->buffer[idx] != '\r' || ev->buffer[idx + 1] != '\n'));

	if (idx == -1)
		return -1;
	return 0;
}

void umask(char* payload, int length, char* mask_key)
{
	for (int i = 0; i < length; ++i)
	{
		payload[i] ^= mask_key[i % 4];
	}
}

// th length of ws_ophdr  whitout mask_key
#define WS_OPHDR_LENGTH 2
int tranmission(struct ntyevent* ev)
{
	ws_ophdr* hdr = (ws_ophdr*)ev->buffer;

	printf("length: %d\n", hdr->payload_length);

	char* payload = NULL;

	if (hdr->payload_length < 126)
	{
		payload = ev->buffer + sizeof(ws_ophdr);
		if (hdr->mask) 
		{
			umask(payload, hdr->payload_length, hdr->mask_key);
		}
	}
	else if (hdr->payload_length == 126)
	{
		ws_head_126* hdr126 = (ws_head_126*)(ev->buffer + WS_OPHDR_LENGTH);
		payload = ev->buffer + WS_OPHDR_LENGTH + sizeof(ws_head_126);
		if (hdr->mask)
		{
			umask(payload, hdr126->payload_length, hdr->mask_key);
		}
	}
	else
	{
		ws_head_127* hdr127 = (ws_head_127*)(ev->buffer + WS_OPHDR_LENGTH);
		payload = ev->buffer + WS_OPHDR_LENGTH + sizeof(ws_head_127);
		if (hdr->mask)
		{
			umask(payload, hdr127->payload_length, hdr->mask_key);
		}
	}
	printf("payload : %s\n", payload);
	return 0;
}

int websocket_request(struct ntyevent* ev)
{
	if (ev->status_machine == WS_HANDSHARK)
	{
		handshark(ev);
		ev->status_machine = WS_TRANMISSION;
	}
	else if (ev->status_machine == WS_TRANMISSION)
	{
		tranmission(ev);
	}
	else
	{
	}

	return 0;
}



int recv_cb(int fd, int events, void* arg)
{
	struct ntyreactor* reactor = (struct ntyreactor*)arg;
	if (reactor == NULL) return -1;
	struct ntyevent* ev = ntyreactor_idx(reactor, fd);

	//LT
	int len = recv(fd, ev->buffer, BUFFER_LENGTH, 0);
	nty_event_del(reactor->epfd, ev);  //这儿先删除，下面再添加监听，实现对读取完数据的判断; 因为没有对buffer做临界区保护，所以我们只能等send_cb处理完再开启对EPOLLIN的监听，防止数据读写冲突
	if (len > 0)
	{
		ev->length = len;
		ev->buffer[len] = '\0';
		printf("recv[fd=%d], [%d]%s\n", fd, len, ev->buffer);

		websocket_request(ev);

		nty_event_set(ev, fd, send_cb, reactor);
		nty_event_add(reactor->epfd, EPOLLOUT, ev);
	}
	else if(len == 0)
	{
		close(ev->fd);
		//printf("[fd=%d] , closed\n", fd);
	}
	else
	{
		close(ev->fd);  //每次接收完会重新设置监听，因此只有出现错误才会len < 0
		printf("recv[fd=%d] error[%d]:%s\n", fd, errno, strerror(errno));
	}

	return len;
}

int send_cb(int fd, int events, void* arg)
{
	struct ntyreactor* reactor = (struct ntyreactor*)arg;
	if (reactor == NULL) return -1;
	struct ntyevent* ev = ntyreactor_idx(reactor, fd);

	int len = send(fd, ev->buffer, ev->length, 0);
	if (len > 0)
	{
		printf("send[fd=%d], [%d]%s\n", fd, len, ev->buffer);

		nty_event_del(reactor->epfd, ev);
		nty_event_set(ev, fd, recv_cb, reactor);
		nty_event_add(reactor->epfd, EPOLLIN, ev);
	}
	else
	{
		close(ev->fd);

		nty_event_del(reactor->epfd, ev);
		printf("send[fd=%d] error %s\n", fd, strerror(errno));
	}

	return len;
}

int accept_cb(int fd, int events, void* arg)
{
	struct ntyreactor* reactor = (struct ntyreactor*)arg;
	if (reactor == NULL) return -1;

	struct sockaddr_in client_addr;
	socklen_t len = sizeof(client_addr);

	int clientfd;
	if ((clientfd = accept(fd, (struct sockaddr*)&client_addr, &len)) == -1)
	{
		if (errno != EAGAIN && errno != EINTR)
		{
		}
		printf("accept[listendfd=%d] error: %s\n", fd, strerror(errno));
		return -1;
	}

	int flag = fcntl(clientfd, F_GETFL, 0);
	if (fcntl(clientfd, F_SETFL, flag | O_NONBLOCK) < 0)
	{
		printf("%s: fcntl nonblocking failed, %d\n", __func__, MAX_EPOLL_EVENTS);
		return -1;
	}

	struct ntyevent* ev = ntyreactor_idx(reactor, clientfd);

	ev->status_machine = WS_HANDSHARK;
	nty_event_set(ev, clientfd, recv_cb, reactor);
	nty_event_add(reactor->epfd, EPOLLIN, ev);

	printf("new connect [%s:%d], pos[%d]\n",
		inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), clientfd);

	return 0;
}

int init_sock(short port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);

	bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

	if (listen(fd, 20) < 0)
	{
		printf("listen failed : %s\n", strerror(errno));

	}
	return fd;
}

int ntyreactor_alloc(struct ntyreactor* reactor)  //为reactor扩建一个eventblock
{
	if (reactor == NULL) return -1;
	if (reactor->evblk == NULL) return -1;

	struct eventblock* blk = reactor->evblk;
	while (blk->next != NULL)
	{
		blk = blk->next;
	}

	struct ntyevent* evs = (struct ntyevent*)malloc((MAX_EPOLL_EVENTS) * sizeof(struct ntyevent));
	if (evs == NULL)
	{
		printf("ntyreactor_alloc ntyevents failed\n");
		return -2;
	}
	memset(evs, 0, ((MAX_EPOLL_EVENTS) * sizeof(struct ntyevent)));

	struct eventblock* block = (struct eventblock*)malloc(sizeof(struct eventblock));
	if (block == NULL)
	{
		printf("ntyreactor_alloc eventblock failed\n");
		return -2;
	}
	memset(block, 0, sizeof(struct eventblock));

	block->events = evs;
	block->next = NULL;

	blk->next = block;
	++(reactor->blkcnt);

	return 0;
}

struct ntyevent* ntyreactor_idx(struct ntyreactor* reactor, int sockfd)
{
	int blkidx = sockfd / MAX_EPOLL_EVENTS;

	while (blkidx >= reactor->blkcnt)
	{
		ntyreactor_alloc(reactor);
	}

	struct eventblock* blk = reactor->evblk;
	for (int i = 0; i < blkidx; ++i)
	{
		blk = blk->next;
	}

	return &blk->events[sockfd % MAX_EPOLL_EVENTS];
}

int ntyreactor_init(struct ntyreactor* reactor)
{
	if (reactor == NULL) return -1;
	memset(reactor, 0, sizeof(struct ntyreactor));

	reactor->epfd = epoll_create(1);
	if (reactor->epfd <= 0)
	{
		printf("create epfd in %s err %s\n", __func__, strerror(errno));
		return -2;
	}

	struct ntyevent* evs = (struct ntyevent*)malloc((MAX_EPOLL_EVENTS) * sizeof(struct ntyevent));
	if (evs == NULL)
	{
		printf("ntyreactor_alloc ntyevents failed\n");
		return -2;
	}
	memset(evs, 0, (MAX_EPOLL_EVENTS) * sizeof(struct ntyevent));

	struct eventblock* blk = (struct eventblock*)malloc(sizeof(struct eventblock));
	if (blk == NULL)
	{
		printf("ntyreactor_alloc eventblock failed\n");
		return -2;
	}
	memset(blk, 0, sizeof(struct eventblock));

	blk->events = evs;
	blk->next = NULL;

	reactor->evblk = blk;
	reactor->blkcnt = 1;

	return 0;
}

int ntyreactor_destroy(struct ntyreactor* reactor)
{
	close(reactor->epfd);

	struct eventblock* blk = reactor->evblk;
	struct eventblock* blk_next = NULL;

	while (blk != NULL)
	{
		blk_next = blk->next;

		free(blk->events);
		free(blk);

		blk = blk_next;
	}

	return 0;
}

int ntyreactor_addlistener(struct ntyreactor* reactor, int sockfd, NCALLBACK* acceptor)
{
	if (reactor == NULL) return -1;
	if (reactor->evblk == NULL) return -1;

	struct ntyevent* ev = ntyreactor_idx(reactor, sockfd);

	nty_event_set(ev, sockfd, acceptor, reactor);
	nty_event_add(reactor->epfd, EPOLLIN, ev);

	return 0;
}

int ntyreactor_run(struct ntyreactor* reactor)
{
	if (reactor == NULL) return -1;
	if (reactor->epfd < 0) return -1;
	if (reactor->evblk == NULL) return -1;

	struct epoll_event events[MAX_EPOLL_EVENTS + 1]; 

	int checkpos = 0, i;

	while (1)
	{
		int nready = epoll_wait(reactor->epfd, events, MAX_EPOLL_EVENTS, 1000);
		if (nready < 0)
		{
			printf("epoll_wait error, exit\n");
			continue;
		}

		for (i = 0; i < nready; ++i)
		{
			struct ntyevent* ev = (struct ntyevent*)events[i].data.ptr;


			if ((events[i].events & EPOLLIN) && (ev->events & EPOLLIN))
			{
				ev->callback(ev->fd, events[i].events, ev->arg);
			}
			if ((events[i].events & EPOLLOUT) && (ev->events & EPOLLOUT))
			{
				ev->callback(ev->fd, events[i].events, ev->arg);
			}
		}
	}
}

int main(int argc, char** argv)
{
	unsigned short port = SERVER_PORT; //listen 9999
	if (argc == 2)
	{
		port = atoi(argv[1]);
	}
	struct ntyreactor* reactor = (struct ntyreactor*)malloc(sizeof(struct ntyreactor));
	ntyreactor_init(reactor);

	int i = 0;
	int sockfd[PORT_COUNT] = { 0 };
	for (i = 0; i < PORT_COUNT; ++i)
	{
		sockfd[i] = init_sock(port - i);
		ntyreactor_addlistener(reactor, sockfd[i], accept_cb);
	}

	ntyreactor_run(reactor);

	ntyreactor_destroy(reactor);

	for (i = 0; i < PORT_COUNT; ++i)
	{
		close(sockfd[i]);
	}

	free(reactor);

	return 0;
}