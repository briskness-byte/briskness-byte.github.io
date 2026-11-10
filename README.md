# briskness-byte.github.io

**The NostrComments website has moved to https://nostrcomments.github.io/**
(repository: [nostrcomments/nostrcomments.github.io](https://github.com/nostrcomments/nostrcomments.github.io)).

What is left here, on purpose:

- `index.html`, `thread/index.html`, `embed/index.html` forward to the same page on the new site,
  keeping the query and fragment, so an old "Read the thread: …/thread/?url=…" link in a Nostr note
  opens the same thread there.
- `embed/frame.html` (with `frame.js`, `frame.css` and `lib/`) keeps serving the comment box for sites
  that embedded it from this address before the move. Their Content-Security-Policy allows this
  origin only, so it cannot simply redirect. New embeds use the box on the new site.

This repository must not be deleted, and the `briskness-byte` account must not be renamed: someone
else could then claim this address and serve their own page to every old link and embed.
