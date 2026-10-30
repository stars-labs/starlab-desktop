# Native glass and light refinement

User direction: transparent frosted-glass appearance, light/shadow and refined
UI interaction, preserving the accepted wallet hierarchy.

The native interface uses locally authored static violet/blue ambient light,
translucent top-lit gradients and illuminated panel edges. Primary/secondary
buttons distinguish idle, hover, press and disabled states; input keyboard
focus is clear. No new renderer, animation timer, business state or dependency
was introduced. Engine dependencies remain pinned to `fab8e166`.

Native runtime Shadow was rejected after actual tiny-skia interaction exposed
rectangular partial-redraw trails. Removing it globally also covers automatic
software fallback; depth comes from the remaining gradients and lighting.
This is native compositing, not a claim of browser-style dynamic backdrop blur.

## Verified acceptance

Source `9bbb52d`; [public evidence](evidence/glass-2026-10-04.json) records
release hash and all 58 screenshot hashes. Existing locked tests: 49 passed,
zero failed, one ignored. Formatting, strict all-target Clippy and release
build pass. All 58 normal/narrow snapshots across 29 states pass; full narrow
approval digest, address, controls, setup and backup errors were inspected.

The actual shadow-free release was exercised with hover, press, keyboard Tab,
eight repeated navigation/focus loops and resizing from 1440×900 to 1024×768.
Final screenshots show no repaint trails. Capture timings include subprocess
and X capture overhead and are not an FPS benchmark.

Final screenshots: `/tmp/starlab-desktop-glass-final-shots` and
`/tmp/starlab-desktop-glass-final-native-shots`. Earlier rejected shadow
captures remain separate; they are not accepted evidence. Crypto and prior
real Sepolia transaction acceptance remain unchanged by this presentation work.

## Compact layout follow-up

The user requested a denser layout with less empty space. Outer margins shrink
from 24 to 16 logical pixels, the sidebar from 260 to 240, and the sidebar/content
gap from 24 to 12. Shared cards use 16-pixel padding instead of 20 and a 12-pixel
title/body gap instead of 16. Approval, ceremony, backup and activity spacing
follow the same compact rhythm. Fonts, button targets, ambient materials and
the 1000-pixel form-width ceiling remain unchanged. Sparse forms retain their
natural height rather than stretching to fill unused canvas.

Verification for this follow-up is recorded separately from the earlier glass
release, so the earlier screenshots are not presented as compact-layout proof.

Compact source `a5b4e75`: 49 tests passed, zero failed, one ignored; strict
locked all-target Clippy and formatting pass. All 58 normal/narrow snapshot
cases rendered successfully in 376.78 seconds. [Evidence](evidence/density-2026-10-04.json)
records each image hash. Root independently inspected narrow setup and signing
approval; the full digest, address and approval actions remain readable.
This follow-up uses the debug snapshot harness; no new release build or live
transaction is claimed.
