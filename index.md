---
layout: splash
title: "Home"
permalink: /
---

{% include base_path %}

Welcome — research and writeups on penetration testing, bug bounty and CTF writeups. Browse the latest posts below.

{% if site.posts.size > 0 %}
  <h2>Latest posts</h2>
  {% for post in site.posts limit:6 %}
    {% include archive-single.html post=post %}
  {% endfor %}
{% else %}
  <p>There are no posts yet.</p>
{% endif %}
