---
layout: default
title: Il mio Blog
---
## Ultimi Articoli

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      - {{ post.date | date: "%d/%m/%Y" }}
    </li>
  {% endfor %}
</ul>
