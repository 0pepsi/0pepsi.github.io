---
layout: default
title: null
---

<ul class="post-list">
{% for post in site.posts %}
  <li>
    <span class="date">{{ post.date | date: "%B %-d, %Y" }}</span>
    <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
    {% if post.cover %}
    <div class="cover-thumb"><a href="{{ post.url | relative_url }}"><img src="{{ post.cover | relative_url }}" alt=""></a></div>
    {% endif %}
    <p class="excerpt">{{ post.excerpt }}</p>
    <a class="read" href="{{ post.url | relative_url }}">read the teardown &rarr;</a>
  </li>
{% endfor %}
</ul>
