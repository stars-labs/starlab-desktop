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
