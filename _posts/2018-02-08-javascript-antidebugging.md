---
layout: post
title: JavaScript AntiDebugging Tricks
date: 2018-02-08 12:00:00
categories: posts
en: true
description: List of antidebugging techniques applied to JavaScript (focused on browsers)
keywords: "javascript, antidebugging, antireversing, antitampering, anti-debugging"
authors:
    - X-C3LL
---

__Disclaimer:__ _This post was updated (September 2021)_


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Last summer I spent a lot of time talking with [@cgvwzq](https://twitter.com/cgvwzq) about antidebugging tricks in JavaScript. We tried to find resources or articles were this topic was analyzed, but the documentation is poor and mostly incomplete. You can find little tricks around the net, but we could not find a resource where all of them were collected. So... here comes our quest.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The intention of this article is to collect little tricks (some of them seen already used by malware or comercial products, and other ideas are ours) related to antidebugging in JavaScript.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Keep in mind this: we are not talking about silver bullets. It's JavaScript. With time and coffee you can debug and reverse the logic inside a snippet of JavaScript. What we want to offer is just some ideas to difficult the task of understand what the code does. Indeed what we show here are techniques not related with obfuscation (tons of information and tools are available), they are more oriented to difficult actively the debugging process.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In a general way, the approachs of the techniques shown in this post are:
- Detect unexpected enviroments of execution (we only want to be executed in browsers)
- Detect debugging tools (for example DevTools)
- Code Integrity Controls
- Flow Integrity Controls
- Anti-emulation

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our main idea is to combine the techniques shown here with obfuscation and cryptography. The code is splitted in a serie of encrypted code-blocks were the decryption process of every blocks depends on other blocks previously decrypted. The intended program flow is to jump from encrypted block to encrypted block in a known sequence. If any of our checks detect something "odd",  the program flow changes his natural path and reach fake blocks. So, when we detect someone debugging our code
we just send him to a fake region, keeping the "interesting" parts away from him.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you know more tricks that are not listed here, please contact me at [@TheXC3LL](https://twitter.com/TheXC3LL) so I can add them to this article.

## 0x01 Function redefinitions
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This is for far the most basic and well-known technique used to avoid someone to debug our code. In JavaScript we can redefine the functions that are used usually to retrieve information. For example, console.log() is used to show in the console information about functions, variables, etc. If we redefine this function, and we change his behaviour, we can hide certain information or just fake it. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To see it in action, just run this inside your DevTools:

```javascript
console.log("Hello World");
var fake = function() {};
window['console']['log'] = fake;
console.log("You can't see me!");
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
What we should see is:
```
VM48:1 Hello World
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The second message is not shown because we "disabled" the function with a redefinition to an empty function. But we can be a bit more ingenious and just change his behaviour to show fakec information. To ilustrate it:

```javascript
console.log("Normal function");
// First we save a reference to the original console.log function
var original = window['console']['log'];
// Next we create our fake function
// Basicly we check the argument and if match we call original function with other param.
// If there is no match pass the argument to the original function
var fake = function(argument) {
    if (argument === "Ka0labs") {
        original("Spoofed!");
    } else {
        original(argument);
    }
}
// We redefine now console.log as our fake function
window['console']['log'] = fake;
// Then we call console.log with any argument
console.log("This is unaltered");
// Now we should see other text in console different to "Ka0labs"
console.log("Ka0labs");
// Aaaand everything still OK
console.log("Bye bye!");
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
And if everything works...
```
Normal function
VM117:11 This is unaltered
VM117:9 Spoofed!
VM117:11 Bye bye!
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you played before with "hooking" this will sound familiar to you.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can be even more clever and redefine other functions more interesting in order to control  the code executed in an unexpected way. For example, we can build a snippet based on the code shown before to redefine the eval function. We can pass JavaScript code to the eval function, so this code will be evaluated and executed. __But if we redefine the function, we can run a different code.__ So... what you see is not what you get :).

```javascript
// Just a normal eval
eval("console.log('1337')");
// Now we repat the process...
var original = eval;
var fake = function(argument) {
    // If the code to be evaluated contains 1337...
    if (argument.indexOf("1337") !== -1) {
        // ... we just execute a different code
        original("for (i = 0; i < 10; i++) { console.log(i);}");
    }
    else {
        original(argument);
    }
}
eval = fake;
eval("console.log('We should see this...')");
// Now we should see the execution of a for loop instead of what is expected
eval("console.log('Too 1337 for you!')");
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
And... Yep, we executed a different code (the "for" loop instead of the console.log with the string "Too 1337 for you!").

```
1337
VM146:1 We should see this...
VM147:1 0
VM147:1 1
VM147:1 2
VM147:1 3
VM147:1 4
VM147:1 5
VM147:1 6
VM147:1 7
VM147:1 8
VM147:1 9
````

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Modifying the flow of our program by this way is a cool trick, but as we said at the begin, it is the most basic trick and can be detected and defeated easily. This is because in JavaScript every function has a method toString (or toSource in Firefox) that returns its own code. So it only needs to check if the code of the desire function was changed or not. Of course we can redefine the method toString / toSource, but we are stucked in the same situation: function.toString.toString().

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We will talk more about "hooking" and function redefinitons later, using another aproach based on the __proxy object__.


## 0x02 Breakpoints

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The tools used to debug JavaScript (for example DevTools) has the capacity of block the script execution at an arbitrary point in order to help us to undertand what is happening. This is done with "breakpoints". Using breakpoints when you are debugging helps you to see what happened, what is happening and will happen next, so they are one of the most fundamentals basis of debugging. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you played a bit with a debugger and the x86 family probably you know about the 0xCC instruction. In JavaScript we have an analog instruction called __debugger__. Placing a debugger; sentence inside your code will produce a stop in the execution of your script when the debugger hit that instruction. Example:

```javascript
console.log("See me!");
debugger;
console.log("See me!");
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If you execute this code with your DevTools opened, a prompt asking you to resume the execution will be shown. Until you press "Continue" the script will be blocked at that point. And here comes the next (pretty stupid) trick seen in comercial products: just put a infinte loop of __debugger;__. Some browsers prevents this situation, others not. But the concept inside this is just to annoy the guy debugging your code. The loop will flood you with a torrent of windows asking to resume the execution, so we can't start to
work reversing the script  until this is fixed.

```javascript
setTimeout(function() {while (true) {eval("debugger")
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Other trick related with breakpoints will be explained in next section.

## 0x03 Differences of time

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Another trick borrowed from classic anti-reversing techniques is to use checks based on time. When a script is executed with DevTools (or similar), the execution time is markedly slowed. This situation can be abused by us using the time as a little canary that tells us if we are being debugged or not. This aproach can be done in differentes ways. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
For example we can measure the elapsed time betweeen two or more points inside the code. If we know the elapsed mean time between those points in "natural" conditions we can use this value as a reference. An elapsed time bigger than the expected would mean that we are being under a debugger.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Other idea based on this topic is to have some functions with loops or another "heavy" code wich execution time is known:

```javascript
setInterval(function(){
  var startTime = performance.now(), check, diff;
  for (check = 0; check < 1000; check++){
    console.log(check);
    console.clear();
  }
  diff = performance.now() - startTime;
  if (diff > 200){
    alert("Debugger detected!");
  }
}, 500);
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
First run that code without DevTools opened and later open it. As you can see we could detect the presence of a debugger because the time difference was greater than the expected. This approach to using time references as a canary can be combined with what is shown in the previous section. So we can take a time reference before and after a breakpoint. If the breakpoint is executed, the amount of time lost before we can resume the execution will reveal the presence of a debugger.

```javascript
    var startTime = performance.now();
    debugger;
    var stopTime = performance.now();
    if ((stopTime - startTime) > 1000) {
        alert("Debugger detected!")
    }
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
These time checks can be placed at random points inside the code so it will be harder to the analyst to spot them.

## 0x04 DevTools detection (I) [Chrome]: getter
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The first time I saw this technique was in this [Reddit Post](https://www.reddit.com/r/firefox/comments/5gtedd/ublock_origin_developer_raymond_hill_on/dav4iiu/). As is said in the post:

>_The technique used is to implement a getter on the id property of a div element. When that div element is sent to the console like console.log(div);, the browser automatically tries to get the id of the element for convenience. Hence, if the getter is executed after calling console.log, this means the console is opened._

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
A simple Proof of Concept:
```javascript
let div = document.createElement('div');
let loop = setInterval(() => {
    console.log(div);
    console.clear();
});
Object.defineProperty(div, "id", {get: () => { 
    clearInterval(loop);
    alert("Dev Tools detected!");
}});
```

## 0x05 DevTools detection (II): size changes
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If DevTools is opened (unless it was opened as undocked) the difference between __window.outerWidth/Height__ and __window.innerWidth/Height__ will change, so it can be measured in a loop. This trick is used by [Devtools-detect](https://github.com/sindresorhus/devtools-detect):

```javascript
        const widthThreshold = window.outerWidth - window.innerWidth > threshold;
        const heightThreshold = window.outerHeight - window.innerHeight > threshold;
        const orientation = widthThreshold ? 'vertical' : 'horizontal';
```



## 0x06 DevTools detection (III): SourceMap
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This technique was explained by [@WeizmanGal](https://twitter.com/WeizmanGal) in his [blog](https://weizman.github.io/website/?javascript-anti-debugging-some-next-level-shit-part-1) and is based on HTTP Leaks via JavaScript source maps. [Source maps](https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map) are files that hold information from the original JavaScript file before it gets minified/uglyfied, so this information can be used by the browser DevTools in order to facilitate the debugging process. The source map file associated with a script is set adding the line __//# sourceMappingURL=http://server/YourFileLocation__ to the end, and it is fetched when the DevTools are opened. This HTTP leak can be used as a canary to notify the fact that someone is opening the DevTools but also can be used to determine what flow the program must follow.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can add constraints to our code to veer the program flow to reach fake regions or just to stop decrypting the code because the key is derived from the value used as constraint. This value used to take one direction or another can be, for example, a cookie. And here comes an interesting fact: __we can set a cookie when our server is requested for a source map file__. So, we can check in our code the value of a cookie that will be set or changed only when the browser fetchs our source map file __:)__. 

```html
<html>
     <head>
         <script>
      // From https://weizman.github.io/website/?javascript-anti-debugging-some-next-level-shit-part-1
    function  smap(url)  {
         const script = document.createElement('script');
         script.textContent =  `//# sourceMappingURL=${url}`;
         document.head.appendChild(script);
         script.remove();  // that's right! the script doesn't even have to stay in DOM for this feature to work! how cool is that?!
    }
    smap('http://test/devtools.php'); // <?php setcookie("DevTools", "True"); ?>
         </script>
     <script>
    function getCookieValue(a) {
        var b = document.cookie.match('(^|[^;]+)\\s*' + a + '\\s*=\\s*([^;]+)');
        return b ? b.pop() : '';
    }

    setInterval( () => { 
            if (getCookieValue("DevTools") == "True") {
            alert("DevTools opened!");
        }
         }, 100);
     </script>
     </head>
     <body>
         <h1>Testing SourceMappingURL</h1>
     </body>
 </html>
```
## 0x07 DevTools detection (IV): Scope Pane
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This technique was also explained by [@WeizmanGal](https://twitter.com/WeizmanGal) in his [blog](https://weizman.github.io/?javascript-anti-debugging-some-next-level-shit-part-2) and consists in the abuse of DevlTools' [Scope Pane](https://developer.chrome.com/docs/devtools/javascript/#check-values). The Scope Pane needs to evaluate the JavaScript in order to represent the expected value, so we can smuggle inside a function a small canary that will be triggered when someone tries to debug it. Also our canary is going to be executed while the main thread is paused, so it can give a few extra headaches.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Example:

```javascript
function malicious() {
    const detect = (function(){
        const dummy = /./;
        dummy.toString = () => {
            alert('someone is debugging the malicious function!');
            return 'SOME_NAME';
        };
        return dummy;
    }());

    // do a malicious action
    if (window.stealUserCookies) window.stealUserCookies();
}

function legit() {
    // do a legit action
    return 1 + 1;
}

function main() {
    legit();
    malicious();
}
main();
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Put a breakpoint inside `malicious()` and enjoy the alert!


## 0x08 Implicit control of flow integrity

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
One of the first steps when we try to deobfuscate a JavaScript snippet is start to rename some variables and functions in order to clarify the source code. You just split the code in smaller chunks of code and begin renaming here and there. In JavaScript we can check if the name of a function has changed or keep the same name. Or to be more correct we can check if the stack trace contains the original names and the original order.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
With __arguments.callee.caller__ we can create a stack trace where we save the functions executed previously. We can use this information to generate a hash that will be the seed used to generate the key to decrypt other parts of our JavaScript. In this way we have an implicit control of the flow integrity because if a function is renamed or the order of functions to be executed is slightly different, the hash created will be totally different. If the hash is different, the key generated will be different too. If the key is different, we can't decrypt the code. To understand it better see next example:

```javascript
function getCallStack() {
    var stack = "#", total = 0, fn = arguments.callee;
    while ( (fn = fn.caller) ) {
        stack = stack + "" +fn.name;
        total++
    }
    return stack
}
function test1() {
    console.log(getCallStack());
}
function test2() {
    test1();
}
function test3() {
    test2();
}
function test4() {
    test3();
}
test4();
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When you execute this code you will see the string `#test1test2test3test4`. If we modify (I invite you to do it) the name of any function the returned string will be different too. We can calculate a secure hash with that string and use it later as seed to derive the key used to decrypt other code-blocks. An interesting point here is that if we can not decrypt the next code-block because the key is invalid (the analyst changed a function name) __we can catch the exception and redirect the execution flow to a fake path__. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Keep in mind that this trick needs to be combined with strong obfuscation to be useful.

## 0x09 Implicit control of code integrity

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
At the end of section "0x01 Function redefinitions" we mentioned that we can retrieve the code of a function in JavaScript with toString() method. As we said, this can be useful to check if a function was redefined, and indeed, this very same idea can be used to know if the code of a function was modified. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The less efective way to do it is to calculate the hash of functions or code blocks and compare it with a pre-known table. But this approach is really stupid. A more realistic and efective approach can be repeat the same strategy that we used before with the stack traces. We can calculate the hash of a chunk of code and use it as a key to decrypt other blocks of code.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The most beautiful idea in order to create an implicit integrity control is to use __collisions in md5__. This idea was coined by [@cgvwzq](https://twitter.com/cgvwzq) after few beers last summer. Basicly we can create functions where its own md5 is tested inside the own function. In order to perform the check __inside the function__ we need to play with collisions (we want to create something like `function(){ if (md5(arguments.callee.toString() === '<md5>') code_function; }`.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The concept behind this technique is the same used to generate image files wich md5 checksum is shown in the own picture. Here is an classic example: a gif showing his own md5 checksum.

![md5 gif](https://shells.aachen.ccc.de/~spq/md5.gif)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
About how to create this type of collisions there are tons of articles (even appeared some examples in PoC||GTFO) but the first one I read and could replicate was [this with PHP](https://natmchugh.blogspot.com.es/2014/10/how-i-made-two-php-files-with-same-md5.html). You can precalculate pretty fast the blocks needed to generate the collisions. Indeed [here](https://gist.github.com/cgvwzq/c70901dc46aeb8a3d70dc70177428a30) is an example created by [@cgvwzq](https://twitter.com/cgvwzq) were the integrity of the function content is checked by this way.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we stated before we need to use strong obfuscation with this kind of techniques.

## 0x0A Proxy Objects (OLD, deprecated)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The proxy object is one of the most useful tools introducted recently in the world of JavaScript. This object can be used to snoop inside other objects, change its behavior (like a hook), or trigger an action under certain circumstances. For example if we want to trace every call to __document.createElement__ and log this information we can create a proxy object:

```javascript
const handler = { // Our hook to keep the track
    apply: function (target, thisArg, args){
        console.log("Intercepted a call to createElement with args: " + args);
        return target.apply(thisArg, args)
    }
}

document.createElement = new Proxy(document.createElement, handler) // Create our proxy object with our hook ready to intercept
document.createElement('div');
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Then we will see that when we call createElement its args will be logged in console:

```
VM64:3 Intercepted a call to createElement with args: div
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
That is great! We can use this to help us to debug code via the interception of some well-known functions (a là strace / ltrace). But as we saw in section __"0x01 Function redefinitions"__ we can use this very same approach to hide or fake information, or just to run code different to what we see (you can simply replace the logic inside the hook show in the example). This kind of function hooking is far better than a simple redefinition.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our main focus in this humble article is to provide some ideas to use as antidebugging tricks, so... can we detect if the analyst is using a proxy object? Indeed we can, but this is a cat and mouse game. For example, using the same code snippet, we can try to call __toString__ method and catch the exception:


```javascript
// Call a "virgin" createElement:
try {
    document.createElement.toString();
} catch(e){
    console.log("I saw your proxy!");
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Here all still ok:
```
"function createElement() { [native code] }"
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
But when we use the proxy...
```javascript
//Then apply the hook
const handler = { 
    apply: function (target, thisArg, args){
        console.log("Intercepted a call to createElement with args: " + args);
        return target.apply(thisArg, args)
    }
}
document.createElement = new Proxy(document.createElement, handler);

//Call our not-so-virgin-after-that-party createElement
try {
    document.createElement.toString();
} catch(e) {
    console.log("I saw your proxy!");
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Yep, we could detect that proxy:
```
VM391:13 I saw your proxy!
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we said: this is just a mouse and cat game. We can add the toString method:

```javascript
const handler = { 
    apply: function (target, thisArg, args){
        console.log("Intercepted a call to createElement with args: " + args);
        return target.apply(thisArg, args)
    }
}
document.createElement = new Proxy(document.createElement, handler);
document.createElement = Function.prototype.toString.bind(document.createElement); //Add toString
//Call our not-so-virgin-after-that-party createElement
try {
    document.createElement.toString();
} catch(e) {
    console.log("I saw your proxy!");
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Now our detection will fail:
```
"function createElement() { [native code] }"
```

## 0x0B Proxy Objects
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The exception trick can not be used anymore. Luckly, we can still detecting the use of proxy objects via __toString__ length. For example, a naive `document.createElement` has a size of 42 (Chrome):

```javascript
document.createElement.toString().length
42
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
On the other hand, this value will change when we create a proxy:

```javascript
const handler = {
    apply: function(target, thisArg, args) {
        console.log("Intercepted call");
        return target.apply(thisArg, args);
    }
}

document.createElement = new Proxy(document.createElement, handler);

document.createElement.toString().length
29
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So we can do something like:

```javascript
if (document.createElement.toString().length < 30) {
    console.log("I saw your proxy");
}
else {
    console.log("Not a proxy");
}
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This trick can not be used in windoww object, but still being useful.

## 0x0C Restrictional enviroments
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we stated in the introduction, one of the things that we want is to try to detect if the code is being executed inside the right enviroment. What we call "the right enviroment" is:

- The code is being executed in a browser (not an emulator, not NodeJS, ...)
- The code is being executed in the domain / resource destinated to it (not a local server)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
For example, an easy check that we can perform to prove if the code is executed locally is:

```javascript
// Pretty stupid idea found in commercial software
if (location.hostname === "localhost" || location.hostname === "127.0.0.1" || location.hostname === "") {
    console.log("Don't run me here!")
}

```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If we run this JavaScript snippet inside a local html we will see the message:
```
VM28:3 Don't run me here!
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Following this idea another option to check is the handler used to open the document (something like `if (location.protocol == 'file:'){...}`) or try to test via HTTP requests if other resources (images, css, etc.) are available. Of course all of these methods are extremely easy to bypass.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
A bit more interesting idea is to avoid the execution if the code is executed in NodeJS (or as we repated in this article: change the flow to a faked path). This is dangerous but I saw in the wild people using NodeJS to [solve JavaScript challenges and bypass anti-bruteforcing mitigations](https://www.tarlogic.com/blog/automatizando-desafios-javascript-nodejs-python/).


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can try to detect the existence of objects that only exists in a browser context:

```javascript
//Under NodeJS
   try { 
..   console.log(window); 
   } catch(e){ 
..      console.log("NodeJS detected!!!!"); 
   }
 
NodeJS detected!!!!
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
And viceversa: in NodeJS we have objects that does not exists in a browser context.

```javascript
//Under the browser
console.log(global)
VM104:1 Uncaught ReferenceError: global is not defined
    at <anonymous>:1:13

//Under NodeJS
  console.log(global)
{ console: 
   Console {
     log: [Function: bound log],...
     ...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can search for tons of metadata that exists only in a browser. Some ideas of this kind that we can retrieve can be seen in the [Panopticlick Project](https://panopticlick.eff.org).


## 0x0D Unimplemented syntax
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Most tools used to debug / sandbox JavaScript code (JSDetox, JSUnpack, etc.) has old engines, so we can use syntax quirks that are recently implemented to break the parser. For example, the exponential operator (__**__) can not be parsed by JSUnpack (__SyntaxError: Missing) after argument list__) and JSDetox (__Unexpected token *__).

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Another trick related with syntax is the usage of [destructuring assignment](https://hacks.mozilla.org/2015/05/es6-in-depth-destructuring/) to set values. For example, a simple `window.top.location = 'JavaScript:alert(1337)'` can be expressed as `[{0:top[(0).toString.call(477066499943,30)]}] = [['JavaScript:alert(1337)']]. Old parsers will break with this syntax __:)__ .

## 0x0E WebGL
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We will not talk about anti-reversing or obfuscation inside WebGL because you can find tons of information in the net (and WebGL is dark and full of terrors). Instead of that we will mention the use of WebGL to process data and interact with the JavaScript, so if someone tries to "emulate" our snippet of JavaScript he will need to provide WebGL support to his emulator.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can implement a simple algorithm (like a multicolor fractal, for example) to create images based on various seeds, then extract the value of pixels at predefined positions and use it as key to decrypt code-blocks. I want to talk in deep about this topic in the future, so I let this section as a stub :P

## Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I hope this collection of tricks can be helpful for you. If you know more, or notice any error or possible improvement of this article, feel free to ping me at my twitter [@TheXC3LL](https://twitter.com/TheXC3LL). 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Kudos to [@cgvwzq](https://twitter.com/cgvwzq) for his help :)

Byt3z!

