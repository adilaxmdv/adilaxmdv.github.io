---
layout: archive
title: "Notes"
permalink: /notes/
tags: [notes]
---

{% include base_path %}

{% assign tag = page.tags | first %}
{% if site.tags[tag] %}
	{% for post in site.tags[tag] %}
		{% include archive-single.html post=post %}
	{% endfor %}
{% else %}
	<p>No notes yet.</p>
{% endif %}
