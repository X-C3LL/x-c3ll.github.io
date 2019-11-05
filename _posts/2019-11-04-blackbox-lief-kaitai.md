---
layout: post
title: Isolating the logic of an encrypted protocol with LIEF and kaitai
date: 2019-11-01 12:00:00
categories: posts
en: true
description: Article describing how we used LIEF to isolate target functions and kaitai to describe the protocol.
keywords: "kaitai, lief, red-team, red team, hacking, reversing, custom protocol, firmware, binary instrumentation"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Last weekend a friend of mine asked me for help with a personal project. He is researching a proprietary protocol used by a particular device to communicate with other devices in the same network in a master-slave schema. He already reversed the protocol almost entirely except a key part: the "payload" or "command" field. It is sent encrypted and we have not enough skills to reverse the algorithm used in short time. The main point of his project is to build tools to research these devices and do the usual stuff: fuzzing, MitM, etc. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The encryption / decryption logic is located in a function inside the main binary, so instead of doing a full reversing to undertand the logic behind (that could take looong time and as I said our skills are low) we want to "isolate" and replicate it outside the binary. This way we can call the decryption / encryption functions as we need in our tools. The ideas that came to my mind in order to build a MitM and decrypt the encrypted "command" were:

- Reverse the algorithm logic and reimplement it. As I said I had no time to take this path (and to be honest I am too lazy).

- Intrument the binary and hook the function (or just attach a debugger and dump the decrypted info from memory). This approach can be taken if we patch some parts of the binary (because it does few checks to verify some parts of the communication like client IDs and nonces) but has drawbacks. The binary is BIG and has tons of other functionalities that we are not interested that must be patched too. We are interested in a "portable" solution and this is far away from it.

- Use [Radare2 ESIL](https://radare.gitbooks.io/radare2book/disassembling/esil.html) to emulate the encryption / decryption logic. This idea is cool because we can do a portable solution with r2pipe. Of course it has its drawbacks too but is a solution that fits our needs. 

- Extract the functions from the main binary to a library with [LIEF](https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html). I remembered [this post where this tool is used to expose and fuzz an internal function](https://blahcat.github.io/2018/03/11/fuzzing-arbitrary-functions-in-elf-binaries/). Our binary is a PIE executable (x86_64) so it is the perfect scenario to use it. Let's go!

## Extracting the target functions
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we said before, is it easy to spot the functions that decrypt / encrypt the payload just following the program flow with a debugger. Indeed we know that it uses 3 arguments (a pointer to the encrypted command, a pointer to a buffer to save the decrypted command and a sizer) and returns a status code if it fails:

```
[0x7ff45af70c20]> db 0x55b2646ec960
[0x7ff45af70c20]> dc
hit breakpoint at: 55b2646ec960
[0x55b2646ec960]> pd 6
            ;-- rip:
|           ; var int local_18h @ rbp-0x18
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|           0x55b2646ec960 b    55             push rbp
|           0x55b2646ec961      4889e5         mov rbp, rsp
|           0x55b2646ec964      4883ec20       sub rsp, 0x20
|           0x55b2646ec968      48897df8       mov qword [local_8h], rdi  // Pointer to the encrypted string
|           0x55b2646ec96c      488975f0       mov qword [local_10h], rsi // Pointer to the empty buffer
|           0x55b2646ec970      488955e8       mov qword [local_18h], rdx // Size

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
With this schema, where we have a "blackbox" function that is fed with an input and returns the info that we need, it is easy to set a shabby solution based in the usage a debugger. Just put a breakpoint at the return address and read from memory the decrypted string (this can be done trivially with r2pipe or even the GDB's python API). This approach is fine if you want to study what is doing your device but is really "strict" and has limited usability. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can use LIEF to convert the binary in a library that exports our "blackbox" function, so we do not need to care about what this function does under the hood. We only need to set the arguments correctly in our tools and use the output. The conversion process is straight forward:

```python
 import lief
 target = "XXX"
 elf = lief.parse(target)
 elf.add_exported_function(0x00253960, "decrypt_payload")
 elf.write("libXXX.so")
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now we have a "libXXX.so" that exports our target function (located at 0x00253960) and can be called from any tool created by us.

```c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int(*decrypt_payload_t)(char *, char *, size_t);
int main (int argc, char** argv) {
	void* handler = dlopen("./libXXX.so", RTLD_LAZY);
	decrypt_payload_t decrypt_payload = (decrypt_payload_t)dlsym(handler, "decrypt_payload");
	...
	decrypt_payload(encrypted, buffer, size); // encrypted is read from STDIN so we can interact easily
	...

}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
That was easy and cool. We can do the same with the function that encrypts the commands, so we can forge our own valid messages.

## Generating a parser with Kaitai Struct
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
[Kaitai Struct](https://kaitai.io/) is a declarative language used to describe binary structures. It has fantastics advantages versus writing the umpteenth parser in your favourite language. For example you only need to describe the structure one time as a __ksy__ file and then you can generate automatically the parser code to a supported language, so you can reuse it in a painless way. I encourage you to start using Kaitai in your projects, it is one of those things that makes your life easier.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As I do not want to spoil the personal project of my friend, I am going to describe a "fake" protocol (indeed is not so fake, just a oversimplification of the real one). Let's say that a packet has the next fields:

__AA__ => [2 bytes] Magic Header

__BB__ => [2 bytes] Version

__CC__ => [2 bytes] Minimum version supported

__DDDD__ => [4 bytes] Device identificator

__EEEE__ => [4 bytes] Sequence number

__FFFF__ => [4 bytes] Sizer

__XX...XX__ => [Sizer bytes] encrypted command


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We know the format of a packet, so let start describing it in a .ksy file (YAML syntax). First we need to set a generic name and the endianness (we are dealing with a big endian format):

```yaml
meta:
	id: fake_protocol
	endian: be
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now we can start defining each field sequentially, with the type (integers, floats...) and the size (more info in the [official documentation](http://doc.kaitai.io/user_guide.html)):

```yaml
meta:
 id: fake_protocol
 endian: be
seq:
 - id: header
   type: u2
 - id: version
   type: u2
 - id: minversion
   type: u2
 - id: device
   type: u4
 - id: seqnumber
   type: u4
 - id: sizer
   type: u4
 - id: command_encrypted
   size: sizer
``` 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The real one is more complicated than this example, but this is enough to understand the basic usage. After describing the structure we need to compile the ksy file with __ksc__:

```
ksc fake.ksy -t python
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Et voilà! Here is the parser autogenerated:

```python
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class FakeProtocol(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = self._io.read_u2be()
        self.version = self._io.read_u2be()
        self.minversion = self._io.read_u2be()
        self.device = self._io.read_u4be()
        self.seqnumber = self._io.read_u4be()
        self.sizer = self._io.read_u4be()
        self.command_encrypted = self._io.read_bytes(self.sizer)
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Accesing the info is trivial:

```python
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
 from pkg_resources import parse_version
 from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO

 (...)                                                                                                                                                                                                                                                                                        
 f = open("captured", "rb")
 ake = KaitaiStream(f)
 data = FakeProtocol(fake)
 print "Version: " + str(data.version)
 print "Device: " + str(hex(data.device))
 print "Sizer: " + str(data.sizer)
 print "Command: \n" + decrypt(data.command_encrypted) # decrypt() calls our binary that decrypts the payload
```

```
mothra@arcadia:/tmp|⇒  python fake.py
Version: 137
Device: 0x13371337
Sizer: 53
Command: (...)
```

## Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Sometimes we have to fight with tasks that can be tedious or apparently too hard. Fortunately there are projects that if you use them wisely they can make your life a lot easier. Here we saw how LIEF and Kaitai Struct saved us hours of work: the toolset to start playing with this propietary protocol was build in few minutes.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The article is more like a personal note to use in the future if I encounter a similar situation again. If it has been helpful to you, or you find an error/typo, feel free to contact me at [@TheXC3LL](https://twitter.com/THEXC3LL).
