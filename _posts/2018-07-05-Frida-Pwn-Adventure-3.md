---
layout: post
title: Hacking a game to learn FRIDA basics (Pwn Adventure 3)
date: 2018-07-05 13:00:37
categories: posts
en: true
description: Learn the basic usage of Frida with this tutorial. Build your own cheat with Frida.
keywords: "Pwn Adventure 3, GhostInTheShell, Frida, Cheat, Game Hacks, Reversing"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Recently I saw that [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) started a serie of videos about how to "hack" a game  released as a CTF challenge at Ghost in the Shellcode in 2015. After watching the two or three first videos I decided to use the same game to explain some aspects of [Frida](https://www.frida.re/) and how this amazing project can save your ass at your work. 

 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 So in this article we are going to build a __cheat__ that will helps us in the game. Takeaways for the reader:
- Hook functions easily with Frida
- Read memory
- Write memory
- Call binary functions inside our hooks
- Deal with clases & structs


 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 First of all, please check [this link](https://github.com/LiveOverflow/PwnAdventure3) in order to setup a server instance. If you have your server and your client ready, let's play! __:)__

## 0x00 The first step: recon!
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The first step should be to launch the client, register a new player, and start exploring the world. After you spent some minutes moving around the map and checking the HUD (mana, life, items...) it is time to move on and get our hands dirty with the terminal. With the game running, do a `ps -aux` and check the name of the main binary used for the client: __PwnAdventure3-Linux-Shipping__. It is a dynamic linked binary with symbols (use `file` to see it), so is highly probable that the "core" of interesting things are located inside a shared object. We can use `ldd` to list easily all the shared objects used by the binary:

```
mothra@kaiju:~/holydays|⇒  ldd $(locate PwnAdventure3-Linux-Shipping)
        linux-vdso.so.1 (0x00007fff5e6c2000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f5af4631000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f5af442d000)
        libGameLogic.so => /home/mothra/PwnAdventure3_Data/PwnAdventure3/PwnAdventure3/Binaries/Linux/libGameLogic.so (0x00007f5af3f61000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f5af3d59000)
        libopenal.so.1 => /home/mothra/PwnAdventure3_Data/PwnAdventure3/PwnAdventure3/Binaries/Linux/../../../Engine/Binaries/Linux/libopenal.so.1 (0x00007f5af3b02000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f5af3801000)
        libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f5af34f6000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f5af32e0000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5af2f35000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5af484e000)
        libssl.so.1.0.0 => /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0 (0x00007f5af2cd4000)
        libcrypto.so.1.0.0 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0 (0x00007f5af28d7000)
```
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 Looks like "libGameLogic.so" is our target. As the game was programmed in C++, we have to deal with [name mangling](https://en.wikipedia.org/wiki/Name_mangling). In order to dump all the exports and translate the name we are going to use a small script that uses Frida and cxxfilt:


```python
# Extract exports & demangle it

import frida
import cxxfilt


session = frida.attach("PwnAdventure3-Linux-Shipping")
script = session.create_script("""
    var exports = Module.enumerateExportsSync("libGameLogic.so");
    for (i = 0; i < exports.length; i++) {
        send(exports[i].name);
    }
        """);

def on_message(message, data):
    print message["payload"] + " - " + cxxfilt.demangle(message["payload"])

script.on('message', on_message)
script.load()
 ```
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
What are we doing here? We are attaching ourself to the running game process (PwnAdventure3-Linux-Shipping), then we create a script (JavaScript) where the main logic lies. From this JavaScript snippet we can access to the Frida API, and all the magic will come true __:)__: with __Module.enumerateExportsSync(libname)__ we are going to retrieve an array with all the exports, then we iterate over the array and pass the information to the main python script using __send()__. In the python we just call __cxxfilt.demangle()__ to demangle the name.

  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  Now we have a nice dump of useful information where we can perform searchs. For example let search for methods related with speed:

  ```
mothra@kaiju:~/holydays|⇒  python demangle-exports.py > demangled.txt
mothra@kaiju:~/holydays|⇒  cat demangled.txt | grep -i speed
_ZN6Player12GetJumpSpeedEv - Player::GetJumpSpeed()
_ZThn168_N6Player12GetJumpSpeedEv - non-virtual thunk to Player::GetJumpSpeed()
_ZN6Player15GetWalkingSpeedEv - Player::GetWalkingSpeed()
_ZThn168_N6Player15GetWalkingSpeedEv - non-virtual thunk to Player::GetWalkingSpeed()
```

## 0x01 Talking to our cheat
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Usually we are not going to need to use the cheats all the time. Maybe we only want to increment our walking speed to travel long distances, but inside buildings we want the normal speed, or even to teleport ourself to another location we need to pass the coordinates as argument. To solve it, the best option is to use the game chat. Use our export dump to search for the "chat" word:

```
mothra@kaiju:~/holydays|⇒  cat demangled.txt | grep -i chat
_ZN6Player11ReceiveChatEPS_RKSs - Player::ReceiveChat(Player*, std::string const&)
_ZN11ClientWorld4ChatEP6PlayerRKSs - ClientWorld::Chat(Player*, std::string const&)
_ZN10LocalWorld13SendChatEventEP6PlayerRKSs - LocalWorld::SendChatEvent(Player*, std::string const&)
_ZN20GameServerConnection11OnChatEventEP6Player - GameServerConnection::OnChatEvent(Player*)
_ZN11ServerWorld4ChatEP6PlayerRKSs - ServerWorld::Chat(Player*, std::string const&)
_ZN11ServerWorld13SendChatEventEP6PlayerRKSs - ServerWorld::SendChatEvent(Player*, std::string const&)
_ZN13ClientHandler4ChatEv - ClientHandler::Chat()
_ZN11ClientWorld13SendChatEventEP6PlayerRKSs - ClientWorld::SendChatEvent(Player*, std::string const&)
_ZN6Player4ChatEPKc - Player::Chat(char const*)
_ZN20GameServerConnection4ChatERKSs - GameServerConnection::Chat(std::string const&)
_ZN6Player11PerformChatERKSs - Player::PerformChat(std::string const&)
_ZThn168_N6Player4ChatEPKc - non-virtual thunk to Player::Chat(char const*)
_ZN10LocalWorld4ChatEP6PlayerRKSs - LocalWorld::Chat(Player*, std::string const&)
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
That __Player::Chat(char const*)__ looks really interesting as it receives a pointer to a string (maybe our chat message?). To check it, we are going to hook it and log to console the content of that string:

```python
 # Log chat
 import frida
 import sys

 session = frida.attach("PwnAdventure3-Linux-Shipping")
 script = session.create_script("""
         //Find "Player::Chat"
         var chat = Module.findExportByName("libGameLogic.so", "_ZN6Player4ChatEPKc");
         console.log("Player::Chat() at  address: " + chat);

         Interceptor.attach(chat, {
             onEnter: function (args) { // 0 => this; 1 => cont char* (our text)
                var chatMsg = Memory.readCString(args[1]);
                console.log("[Chat]: " + chatMsg);
             }

         });
 """)

 script.load()
 sys.stdin.read()
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Through __Module.findExportByName(libname, function)__ we get the address of Player::Chat, and then we pass that address to the __Interceptor__ in order to "attach" our hook. Now we can control two events: __onEnter__ and __onLeave__ (the names explain itself). Inside onEnter we can snoop the arguments (keep in mind that the first argument will be [this](https://www.tutorialspoint.com/cplusplus/cpp_this_pointer.htm), so the second argument is our pointer to string). Finally we just need to read the memory with __Memory.readCString(pointer)__ to obtain the string. Execute it and type in the chat something:

```
mothra@kaiju:~/holydays|⇒  python log-chat.py
Player::Chat() at  address: 0x7f4ca4d4d850
[Chat]: This Works
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
At this point we can type commands inside the game chat and parse it to fire the actions programmed in our cheat. Oh, wait, what actions? Keep reading!

## 0x02 Speed! (not the film)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The first thing that we want to do is to move faster. As we stated before, the binary has symbols. Let's dump the symbols related to the Player class:
```
gdb -p  $(pidof PwnAdventure3-Linux-Shipping) --batch -ex "ptype Player" -ex "quit" > Player.class
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Search for speed:

```
mothra@kaiju:~/holydays|⇒  cat Player.class | grep -i speed
    float m_walkingSpeed;
    float m_jumpSpeed;
    virtual float GetWalkingSpeed();
    virtual float GetJumpSpeed();
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Interesting. We got a __m_walkingSpeed__ (float) that looks like the baseline speed used for the walk action and a method called "GetWalkingSpeed()" that (if we cross-check with our demangled dump) corresponds to ___ZN6Player15GetWalkingSpeedEv - Player::GetWalkingSpeed()__. We can hook GetWalkingSpeed so every time it is called the value of m_walkingSpeed is overwritten with our desired speed.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To get the memory position of m_walkingSpeed I gonna calculate it as an offset from `this` when GetWalkingSpeed() is called (I saw this method in this post of FuzzySecurity -[Application Introspection & Hooking With Frida](http://www.fuzzysecurity.com/tutorials/29.html)-). With GDB it is easy peasy:

```
mothra@kaiju:~/holydays|⇒  gdb -p  $(pidof PwnAdventure3-Linux-Shipping) --batch 
\ -ex "b _ZN6Player15GetWalkingSpeedEv" --ex "c" --ex "print &this->m_walkingSpeed" 
\ -ex "print this" -ex "print (int)\$1-(int)\$2" -ex "quit" 2>/dev/null | awk '/\$3/ {print $3 }'
736
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So our roadmap now is: 1, hook ___ZN6Player15GetWalkingSpeedEv; 2, get `this` pointer at onEnter and add 736 (the offset) to get the position of m_walkingSpeed; 3, overwrite this float with our desired speed (first 9999).

```javascript
// Find Player::GetWalkingSpeed()
         var walkSpeed = Module.findExportByName("libGameLogic.so", "_ZN6Player15GetWalkingSpeedEv");
         console.log("Player::GetWalkingSpeed() at address: " + walkSpeed);

         // Check Speed
         Interceptor.attach(walkSpeed,
             {
                 // Get Player * this location
                 onEnter: function (args) {
                     console.log("Player at address: " + args[0]);
                     this.walkingSpeedAddr = ptr(args[0]).add(736) // Offset m_walkingSpeed
                     console.log("WalkingSpeed at address: " + this.walkingSpeedAddr);
                 },
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Keep an eye on how we now have the memory address of m_walkingSpeed in  __walkingSpeedAddr__, so we can access to this value inside the onLeave event:

```javascript
                 // Get the return value and write the new value
                 onLeave: function (retval) {
                     console.log("Walking Speed: " + Memory.readFloat(this.walkingSpeedAddr));
                     Memory.writeFloat(this.walkingSpeedAddr, 9999);

                 }
             });
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we did before with readCString, now we are using __Memory.readFloat__ to read the original speed value (200) and log it in the terminal. Lastly, we write the new walking speed as a float (9999). Launch it and move around the map. Crazy speed is crazy!

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we had our routine to get the chat messages, we can use it to regulate the speed with __!wspeed_on NUMBER__ and __!wspeed_off__:
```javascript

script = session.create_script("""
        // Global Values
        var Player = {
            m_walkingSpeed : 200,
        };

        // Cheat status
        var cheatStatus = {
            walkingSpeed : 0,
        };

        // Chat Helper
        function chatHelper(msg) {
            var token = msg.split(" ");
            if (token[0] === "!wspeed_on") {
                Player.m_walkingSpeed = parseInt(token[1]);
                cheatStatus.walkingSpeed = 1;
                console.log("[CHEAT]: Walking Speed Enabled (" + token[1] + ")");
            }
            if (token[0] === "!wspeed_off") {
                Player.m_walkingSpeed = 200;
                cheatStatus.walkingSpeed = 0;
                console.log("[CHEAT]: Walking Speed Disabled (200)");
            }
        }


        //Find "Player::Chat"
        var chat = Module.findExportByName("libGameLogic.so", "_ZN6Player4ChatEPKc");
        console.log("Player::Chat() at  address: " + chat);

        // Add our logger
        Interceptor.attach(chat, {
            onEnter: function (args) { // 0 => this; 1 => cont char* (our text)
               var chatMsg = Memory.readCString(args[1]);
               console.log("[Chat]: " + chatMsg);
               chatHelper(chatMsg);
            }

        });

        // Find Player::GetWalkingSpeed()
        var walkSpeed = Module.findExportByName("libGameLogic.so", "_ZN6Player15GetWalkingSpeedEv");
        console.log("Player::GetWalkingSpeed() at address: " + walkSpeed);

        // Check Speed
        Interceptor.attach(walkSpeed,
            {
                // Get Player * this location
                onEnter: function (args) {
                    //console.log("Player at address: " + args[0]);
                    this.walkingSpeedAddr = ptr(args[0]).add(736) // Offset m_walkingSpeed
                    //console.log("WalkingSpeed at address: " + this.walkingSpeedAddr);
                },

                // Get the return value and write the new speed
                onLeave: function (retval) {
                    if (Memory.readFloat(this.walkingSpeedAddr) != Player.m_walkingSpeed && cheatStatus.walkingSpeed == 0) {
                        Memory.writeFloat(this.walkingSpeedAddr, 200);
                    }
                    if (cheatStatus.walkingSpeed == 1) {
                        Memory.writeFloat(this.walkingSpeedAddr, Player.m_walkingSpeed);
                    }
                }
            });

""")
```


## 0x03 TV-Transportation, I mean Teletransportation
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
A nice walking speed is helpful to explore big map areas, but the capacity of spawn ourself in other point of the map is cooler. Let's search again our demangled functions:

```
mothra@kaiju:~/holydays|⇒  cat demangled.txt| grep -i position
_ZN11ServerWorld23SendActorPositionEventsEP6Player - ServerWorld::SendActorPositionEvents(Player*)
_ZN6Player25ShouldSendPositionUpdatesEv - Player::ShouldSendPositionUpdates()
_ZN5Actor28ShouldReceivePositionUpdatesEv - Actor::ShouldReceivePositionUpdates()
_ZN7AIActor25ShouldSendPositionUpdatesEv - AIActor::ShouldSendPositionUpdates()
_ZN5Actor28SetRemotePositionAndRotationERK7Vector3RK8Rotation - Actor::SetRemotePositionAndRotation(Vector3 const&, Rotation const&)
_ZN20GameServerConnection26OnPositionAndVelocityEventEP6Player - GameServerConnection::OnPositionAndVelocityEvent(Player*)
_ZN5Actor11GetPositionEv - Actor::GetPosition()
_ZN4Drop25ShouldSendPositionUpdatesEv - Drop::ShouldSendPositionUpdates()
_ZN6Player28ShouldReceivePositionUpdatesEv - Player::ShouldReceivePositionUpdates()
_ZN10LocalWorld23SendActorPositionEventsEP6Player - LocalWorld::SendActorPositionEvents(Player*)
_ZN6Player15GetLookPositionEv - Player::GetLookPosition()
_ZN20GameServerConnection15OnPositionEventEP6Player - GameServerConnection::OnPositionEvent(Player*)
_ZN5Actor15GetLookPositionEv - Actor::GetLookPosition()
_ZN11ClientWorld23SendActorPositionEventsEP6Player - ClientWorld::SendActorPositionEvents(Player*)
_ZN20GameServerConnection21OnPlayerPositionEventEP6Player - GameServerConnection::OnPlayerPositionEvent(Player*)
_ZN5Actor21GetProjectilePositionEv - Actor::GetProjectilePosition()
_ZN10Projectile25ShouldSendPositionUpdatesEv - Projectile::ShouldSendPositionUpdates()
_ZN5Actor25ShouldSendPositionUpdatesEv - Actor::ShouldSendPositionUpdates()
_ZN5Actor25InterpolateRemotePositionEf - Actor::InterpolateRemotePosition(float)
_ZN7AIActor28ShouldReceivePositionUpdatesEv - AIActor::ShouldReceivePositionUpdates()
_ZN5Actor11SetPositionERK7Vector3 - Actor::SetPosition(Vector3 const&)
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
A wild __SetPosition__ appeared! It has as argument a Vector3, which is the coordinates in the axis x, y & z, so this SetPosition is our key to the teleport. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In Frida we can call functions located inside the binary though __NativeFunction__. We need to know:
- Address of the function we want to call
- Return type
- Argument number and type

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As arguments we need to pass the pointer to `this` and our Vector3. The first point is easy to solve: just take it from the chat hook when we call the "!tp" command. To solve the second requirement we are going to ask Frida to allocate a small buffer where we are going to write the floats with the information of x, y and z, and then pass the pointer to this buffer to SetPosition.

```javascript
//Teleport
        var setPositionAddr = Module.findExportByName("libGameLogic.so", "_ZN5Actor11SetPositionERK7Vector3");
        var setPosition = new NativeFunction(setPositionAddr, 'void', ['pointer', 'pointer']);
        var Vector3 = Memory.alloc(16);

        function teleport(thisReference, x, y, z) {
            Memory.writeFloat(Vector3, x);
            Memory.writeFloat(ptr(Vector3).add(4), y);
            Memory.writeFloat(ptr(Vector3).add(8), z);
            setPosition(thisReference, Vector3);
        }

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The allocation is easily made calling __Memory.alloc(SIZE)__. Then with __Memory.writeFloat__ we write the values of our desired coordinates (x,y,z) and lastly we call the function. The whole script, including the chat parser, should looks something like this:

```javascript
        // Global Values
        var Player = {
            m_walkingSpeed : 200,
        };

        // Cheat status
        var cheatStatus = {
            walkingSpeed : 0,
        };

        //Teleport
        var setPositionAddr = Module.findExportByName("libGameLogic.so", "_ZN5Actor11SetPositionERK7Vector3");
        var setPosition = new NativeFunction(setPositionAddr, 'void', ['pointer', 'pointer']);
        var Vector3 = Memory.alloc(16);

        function teleport(thisReference, x, y, z) {
            Memory.writeFloat(Vector3, x);
            Memory.writeFloat(ptr(Vector3).add(4), y);
            Memory.writeFloat(ptr(Vector3).add(8), z);
            setPosition(thisReference, Vector3);
        }


        // Chat Helper
        function chatHelper(msg, thisReference) {
            var token = msg.split(" ");
            if (token[0] === "!wspeed_on") {
                Player.m_walkingSpeed = parseInt(token[1]);
                cheatStatus.walkingSpeed = 1;
                console.log("[CHEAT]: Walking Speed Enabled (" + token[1] + ")");
            }
            if (token[0] === "!wspeed_off") {
                Player.m_walkingSpeed = 200;
                cheatStatus.walkingSpeed = 0;
                console.log("[CHEAT]: Walking Speed Disabled (200)");
            }
            if (token[0] === "!tp") {
                console.log("[CHEAT]: Teleporting to " + token[1] + " " + token[2] + " "+ token[3]);
                teleport(thisReference, parseInt(token[1]), parseInt(token[2]), parseInt(token[3]));
         }
        }


        //Find "Player::Chat"
        var chat = Module.findExportByName("libGameLogic.so", "_ZN6Player4ChatEPKc");
        console.log("Player::Chat() at  address: " + chat);

        // Add our logger
        Interceptor.attach(chat, {
            onEnter: function (args) { // 0 => this; 1 => cont char* (our text)
               var chatMsg = Memory.readCString(args[1]);
               console.log("[Chat]: " + chatMsg);
               chatHelper(chatMsg, args[0]);
            }

        });

        // Find Player::GetWalkingSpeed()
        var walkSpeed = Module.findExportByName("libGameLogic.so", "_ZN6Player15GetWalkingSpeedEv");
        console.log("Player::GetWalkingSpeed() at address: " + walkSpeed);

        // Check Speed
        Interceptor.attach(walkSpeed,
            {
                // Get Player * this location
                onEnter: function (args) {
                    //console.log("Player at address: " + args[0]);
                    this.walkingSpeedAddr = ptr(args[0]).add(736) // Offset m_walkingSpeed
                    //console.log("WalkingSpeed at address: " + this.walkingSpeedAddr);
                },

                // Get the return value
                onLeave: function (retval) {
                    if (Memory.readFloat(this.walkingSpeedAddr) != Player.m_walkingSpeed && cheatStatus.walkingSpeed == 0) {
                        Memory.writeFloat(this.walkingSpeedAddr, 200);
                    }
                    if (cheatStatus.walkingSpeed == 1) {
                        Memory.writeFloat(this.walkingSpeedAddr, Player.m_walkingSpeed);
                    }
                }
            });
```

## 0x04 Manna is falling from the sky

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__UPDATE (8/JUL/2018): The mana is getting checked via server, so I failed hard here. I got tricked because we are only setting the value in the HUD :(__

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you walk to the direction of the sun (over the sea) at some point you will find a island with Cows and a quest will be activated. Without making any big spoiler, in this island an NPC will give you a weapon. This weapon wastes mana, and we do not like to waste it (even if it is regenerated fastly). We want our mana always at the max value! 

```
mothra@kaiju:~/holydays|⇒  cat Player.class| grep -i mana
    int32_t m_mana;
    float m_manaRegenTimer;
    virtual int32_t GetMana();
    virtual bool UseMana(int32_t);
    void PerformSetMana(int32_t);
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This situation is almost the same that we saw before with speed, so our modus operandi will be the same. Calcualte the offset of __m_mana__ and then hook __GetMana__ to overwrite the value to 100:

```
mothra@kaiju:~/holydays|⇒  gdb -p  $(pidof PwnAdventure3-Linux-Shipping) --batch 
\ -ex "set verbose off" -ex "b _ZN6Player15GetWalkingSpeedEv" --ex "c" --ex "print &this->m_mana"
\ -ex "print this" -ex "print (int)\$1-(int)\$2" -ex "quit" 2>/dev/null | awk '/\$3/ {print $3 }'

544
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Hook it...
```javascript
        var getMana = Module.findExportByName("libGameLogic.so", "_ZN6Player7GetManaEv");
        console.log("Player::GetMana at address: " + getMana);
        Interceptor.attach(getMana,
        {
            onEnter: function (args) {
                if (cheatStatus.infiniteMana == 1) {
                    m_manaAddr = ptr(args[0]).add(544) // Offset m_mana
                    Memory.writeInt(m_manaAddr, 100);
                }
            }
        }
        );
 ```
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Keep pressed the fire button and check how your mana never get low!


## 0x05 Final Words
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Using Frida to cheat in this game is just a funny way to explain the basics concepts around this framework. If you know better ways (or how to optimize the code) feel free to ping me at twitter [@TheXC3LL](https://twitter.com/thexc3ll). The final cheat code can be found in my github [PwnAdventure3-cheat.py](https://github.com/X-C3LL/snippets/blob/master/PwnAdventure3-cheat.py).

 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
 If you find typo or errors, contact me too __:P__. 









