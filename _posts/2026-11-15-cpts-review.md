---
title: 'CPTS Review'
badge: 'https://images.credly.com/size/340x340/images/e63aa507-b974-4e67-bae6-1e425f6e2a99/image.png'
date: 2026-11-15
permalink: /cpts-review/
tags:
  - notes
  - htb
  - certs
---

![Ladies and gentlemen... I am officially CPTS certified](/images/cpts-meme.png)

Today I want to share my experience about the HTB CPTS certification. Before starting, I hope this blog finds you well.

Okay, let's start from the beginning.

## Background

Before CPTS I had CompTIA PenTest+ and I'm in my 4th year of a BSc in Information Security. Before CPTS I hadn't really done this type of exam, and never did a long journey like this.

## The Journey

It all started one year ago. Yes, it took me a full year, but the path came to an end and I felt completely confident.

I wrote all my notes in Obsidian, synced via Git and Syncthing, and also read them during public transport on my phone.

I went through the modules slowly  - at least 1 hour each day. Sometimes there wasn't time to look into it during the week, so I would make up for that on the weekends.

I kept this pace until September 2026 for the Academy side. After September I started doing machines  - I'll mention my full machine list at the end. Also, 1 week before entering the CPTS exam I did the HTB Pro Lab **Dante**. It's not necessary, but I did it to feed my confidence.

I want to mention that Dante is easier than CPTS. There are no deep rabbit holes compared to CPTS.

The whole Academy modules are important  - I'd say you should focus on each module, especially **AD Enumeration** and **Enumeration of Services**. That's what you really need in the exam.

## The Exam

The exam is 10 days. You get several machines that you need to fully pwn, and before the end of those 10 days you have to write a commercial pentest report and submit it.

I started on a Saturday, and within 5 days I had fully pwned everything. If you're struggling in the exam  - do your research and always go back to the Academy modules before going deep. Check what they taught you, maybe you're missing something. That's exactly what I did, and it helped me hit the 8th flag. Yeah, the 8th flag  - it's the difficult one. The difficulty comes from the chain. You need the mindset to combine things and think outside the box.

## The Report

The report was the easy part for me because I took notes and screenshots while pwning.

I used **SysReptor** with the CPTS template, and I also created findings templates that I'll share with you:
[sysreptor-cpts-kit](https://github.com/adilaxmdv/sysreptor-cpts-kit)

I also used **ShareX** for taking screenshots from Windows.

## My Setup

- VMware + Kali 2026
- Lenovo ThinkPad T14 Gen 6, 32GB RAM, 1TB SSD

## Tools I Recommend

These are the tools I used the most and highly recommend:

- **Ligolo-ng**  - best thing you should learn. You need to feel confident with tunneling and pivoting
- **BloodHound-CE**  - for playing with collected AD data
- **RustHound-CE**  - for collecting data in AD environments
- **NetExec**  - really the best tool ever, you can use it for everything
- **Impacket**  - I think I don't need to say anything about this one

## Final Thoughts

I really recommend this cert and path. Not because it can easily get you a job (maybe, I don't know), but because it gives you real hands-on experience with writing a commercial report and actual penetration testing.

## Machines I Did Before the Exam

**Easy**
- Postman, Trick, Active, Forest, Sauna, Support, Cicada, EscapeTwo, Fluffy, MetaTwo, Soccer, Pandora, Headless, BountyHunter, TwoMillion, Love

**Medium**
- Administrator, Media, TombWatcher, Voleur, POV, Certified, Escape, Manager, Authority, VulnCicada, StreamIO, Jeeves, Builder, Hospital, Craft, Agile, Magic, SecNotes, RedCross, Hawk

**Hard**
- Blackfield, Redelegate, Flight

---

![CPTS Certificate  - Adil Ahmadzada, 12 Nov 2026](/images/cpts-cert.png)
