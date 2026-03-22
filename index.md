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
  {% for post in site.posts limit:6 %}
    {% include archive-single.html post=post %}
  {% endfor %}
{% else %}
  <p>There are no posts yet.</p>
{% endif %}
