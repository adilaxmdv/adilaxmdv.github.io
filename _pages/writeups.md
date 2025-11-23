---
layout: archive
title: "Writeups"
permalink: /writeups/
tags: [writeups]
---

{% include base_path %}

{% assign tag = page.tags | first %}
{% if site.tags[tag] %}
	{% for post in site.tags[tag] %}
		{% include archive-single.html post=post %}
	{% endfor %}
{% else %}
	<p>There are no posts tagged "{{ tag }}" yet.</p>
{% endif %}

