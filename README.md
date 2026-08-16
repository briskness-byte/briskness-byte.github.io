# briskness-byte.github.io

The landing page for [NostrComments](https://github.com/briskness-byte/NostrComments).

**This has to be a user site** — a repository named exactly `briskness-byte.github.io` — and not a
project page under the NostrComments repo. A project page lives at
`briskness-byte.github.io/NostrComments/`, which leaves the host root empty, and every favicon
lookup on the web uses the hostname alone. awesome-nostr builds its icons from
`https://<hostname>/favicon.ico`, so a project page would stay iconless. This way the same repo
answers both.

One hand-written file, no build step, no dependencies — the same claim the extension makes about
itself, so it had better be true here too.

## Setting it up

    git init && git add -A && git commit -m "Landing page"
    git branch -M main
    git remote add origin git@github-brisknessbyte:briskness-byte/briskness-byte.github.io.git
    git push -u origin main

Then Settings → Pages → Source: `main` / root. It is live at https://briskness-byte.github.io/
within a minute or two.

## Before it goes up

- The demo video block is commented out. Uncomment it once the video exists.
