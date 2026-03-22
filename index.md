---
layout: single
title: "Home"
permalink: /
author_profile: true
---

{% include base_path %}

pentester. i break things and write about it.

{% if site.posts.size > 0 %}
  <h2>Latest posts</h2>
  <ul>
  {% for post in site.posts limit:6 %}
    <li>
      <a href="{{ base_path }}{{ post.url }}">{{ post.title }}</a>
      <span style="color: var(--text-muted, #888); font-size: 0.85em; margin-left: 0.5em;">{{ post.date | date: "%Y-%m-%d" }}</span>
    </li>
  {% endfor %}
  </ul>
{% endif %}
