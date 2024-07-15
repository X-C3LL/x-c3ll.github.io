---
layout: default
---

<h1> Index of / </h1>

{% for post in site.categories.posts %}
<div style="font-family: Quantico">
:: <a href="{{ post.url}}" style=""><b>{{ post.title}}</b></a> <br>:: <b>{{ post.date }} </b>::
</div>
{{ post.description }}

{% endfor %}