---
layout: single
title: "writeups"
permalink: /writeups/
author_profile: true
---

{% include base_path %}

{% assign writeup_posts = site.tags["writeups"] %}
{% if writeup_posts %}
  <ul class="writeups-list">
  {% for post in writeup_posts %}
    <li class="writeup-item">
      {% if post.badge %}
        <a href="{{ base_path }}{{ post.url }}">
          <img src="{{ post.badge }}" alt="{{ post.title }}" class="writeup-badge" />
        </a>
      {% endif %}
      <a href="{{ base_path }}{{ post.url }}" class="writeup-title">{{ post.title }}</a>
      <span class="writeup-date">{{ post.date | date: "%Y-%m-%d" }}</span>
    </li>
  {% endfor %}
  </ul>
{% else %}
  <p>No writeups yet.</p>
{% endif %}

<style>
.writeups-list {
  list-style: none;
  padding: 0;
  margin: 1.5rem 0;
}

.writeup-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--border-color, #eee);
}

.writeup-badge {
  width: 48px;
  height: 48px;
  object-fit: contain;
  flex-shrink: 0;
}

.writeup-title {
  flex: 1;
  font-weight: 500;
  text-decoration: none;
}

.writeup-title:hover {
  text-decoration: underline;
}

.writeup-date {
  font-size: 0.8em;
  color: var(--text-muted, #888);
  white-space: nowrap;
}
</style>
