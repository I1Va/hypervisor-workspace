# Reference material

Large vendor documents are kept here but **not versioned** (see `.gitignore`):
a 20 MB binary in git history costs every clone forever, and these are read
rarely and never edited.

| File | What | Where to get it |
|---|---|---|
| `E12543b_Z97-WS_UM_V2_WEB.pdf` | ASUS Z97-WS motherboard manual - header pinouts, ATX pinout, board layout | ASUS support site, or this machine's `~/Downloads/` |

If a document here is missing, the stand still works; only the wiring reference
is unavailable. The facts actually needed from it (which header the reset relay
is across, which pin senses the power LED) are recorded in
`database/bench/platform.md`.
