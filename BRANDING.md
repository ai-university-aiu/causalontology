# Causalontology - Visual Identity

## The palette (official, global)

Causalontology's visual identity is a single warm crimson-to-gold palette.
Use these eight colors - and only these - for badges, charts, diagrams,
dashboards, and any other project visual. They run from a light, bright
gold-yellow down through the oranges and reds into a deep crimson-black.

| # | Hex | Sense |
|---|---|---|
| 1 | `#ffce59` | light bright gold-yellow (the highest honor) |
| 2 | `#ff933a` | warm orange |
| 3 | `#f26d1f` | burnt orange |
| 4 | `#e04217` | red-orange |
| 5 | `#c02b18` | red |
| 6 | `#7c0300` | dark red |
| 7 | `#590000` | deep red |
| 8 | `#3a0000` | crimson-black (the ground) |

## The badge rule

The README badge rack uses the classic shields.io look - a neutral grey
label box on the left (no `labelColor`, matching the PrologAI and Mentova
READMEs) - and, on the right (message) side, a single smooth FADE across
the eight palette colors above, in reading order: the first badge is
`#ffce59`, the last is `#3a0000`, and the badges in between are evenly
interpolated along the palette. One fade, top to bottom, no per-badge
semantic coloring.

To regenerate the fade for N badges, sample N evenly spaced points along
the piecewise-linear path through the eight anchors (badge 1 = anchor 1,
badge N = anchor 8) and write each color into that badge's message-color
slot, dropping any `labelColor`.
