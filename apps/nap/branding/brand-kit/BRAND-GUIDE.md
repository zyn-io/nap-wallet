# Nap Wallet brand kit

Version 1.0 · September 2026

## Brand idea

**Your money, quietly yours.**

Nap Wallet makes serious privacy infrastructure feel calm and approachable. The mole is a quiet guardian: comfortable underground, out of sight, and built for protecting what is private. The wallet is the product. The sleeping pose communicates confidence—not inactivity.

### Personality

- Quietly capable, never loud
- Warm, not childish
- Precise, not clinical
- Reassuring, never complacent
- Private, never mysterious

## Logo system

The primary mark is the sleepy mole resting on a gold wallet. Use the horizontal lockup for marketing, documentation, and wide headers. Use the mark alone when the Nap Wallet name is already visible. Use the light or dark app icon for launchers and profiles.

### Clear space

Keep clear space equal to the mole's nose diameter on every side of the mark. For the horizontal lockup, keep at least the height of the lowercase `a` around the full artwork.

### Minimum sizes

- Horizontal lockup: 180 px digital / 38 mm print
- Standalone mark: 72 px digital / 18 mm print
- App icon: never smaller than the platform-required size; use the simplified SVG master
- Below 32 px, omit the `z z Z` motif if it becomes visually noisy. It does: at 32 px it smears into an orange blur, so the shipped 16 px and 32 px icons use `app-icon-light-small.svg`

### Backgrounds

- Ivory or white: use the standard charcoal mole without an outline.
- Charcoal or photography: use the dark icon treatment with a warm-ivory keyline around the mole.
- Gold: use a single-color charcoal mark.
- Never place the unoutlined charcoal mole directly on a dark field.

### Do not

- Add gradients, bevels, drop shadows, glow, or fur texture
- Turn the mole into a cat: no ears, feline whiskers, or round cat muzzle
- Recolor the wallet with teal; gold always represents stored value
- Stretch, rotate, rearrange, or redraw the lockup casually
- Use the mascot as decorative wallpaper throughout the wallet UI

## Color

| Role | Name | Hex | Usage |
|---|---|---:|---|
| Primary | Burrow Charcoal | `#202326` | Mole, wordmark, primary text |
| Value | Restful Gold | `#E0A51B` | Wallet, balances, value moments |
| Value shadow | Deep Gold | `#A87509` | Clasp and small supporting shapes only |
| Base | Warm Ivory | `#F7F4EA` | Brand backgrounds and dark-logo keyline |
| Character | Snout Taupe | `#BFA58E` | Mole face and paws only |
| Action | Privacy Teal | `#0E6F6E` | Buttons, focus, secure/private states |
| Action tint | Teal Mist | `#D6EBE9` | Private panels and selected states |

Gold says **value**. Teal says **action or privacy**. Do not use the two interchangeably. Large text in gold on ivory may miss accessible contrast; use gold for large display numbers, icons, and fills, and use Deep Gold for smaller text.

## Typography

### Brand/display — Bricolage Grotesque

Use weights 600–700 for the wordmark, campaigns, and major headlines. Its rounded construction echoes the mole without making the financial product feel juvenile.

### Product/body — IBM Plex Sans

Use weights 400–600 throughout the wallet. It is calm, highly legible, and already established in the application.

### Data — IBM Plex Mono

Use for addresses, hashes, amounts in tables, block heights, and verifiable records. Do not use it for explanatory copy.

## Voice

Write like a calm technical guide who respects the reader's intelligence.

### Principles

1. Lead with the outcome: “Sent privately” before protocol detail.
2. Name consequences before mechanisms: “This destroys the item” before “burn.”
3. Keep reassurance factual. Never imply that funds are safe merely because the interface looks calm.
4. Put protocol vocabulary one layer deeper unless it affects the user's decision.
5. Prefer short, concrete sentences.

### Examples

| Avoid | Prefer |
|---|---|
| Proving the payment via Ironwood v6 | Preparing your private payment. About a minute. |
| Transaction broadcast successful | Sent privately. |
| Insufficient spendable notes | Not enough available balance. |
| Force via Zcash | Use Zcash recovery path |

## Product application

- Keep the wallet UI predominantly neutral. The mole appears in onboarding, empty states, successful backup, and recovery guidance.
- Gold is reserved for balances and assets. It should not become the default button color.
- Teal remains the primary action color and signals private/account-specific information.
- Publicly verifiable records remain cool gray and monospaced.
- Motion should be slow and purposeful: a single breathing rise for sleep, a brief burrowing transition, never bouncing coins.

## Recommended short copy

- Brand line: **Your money, quietly yours.**
- Product descriptor: **A private wallet for Zcash and Zyn.**
- Privacy reassurance: **Only this key can see it.**
- Empty activity: **Quiet here. Your private activity will appear after your first transaction.**
- Syncing: **Catching up privately.**

## Asset inventory

- `assets/logo-horizontal.svg` — primary wide lockup
- `assets/mark-color.svg` — transparent standalone mark
- `assets/app-icon-light.svg` — light application icon
- `assets/app-icon-dark.svg` — dark icon with mole keyline
- `assets/app-icon-light-small.svg` — light icon with the `z z Z` motif removed, for 32 px and below
- `assets/brand-tokens.css` — portable design tokens
- `exports/*.png` — raster icon exports

The horizontal wordmark is already converted to vector outlines, so it remains visible without an installed font. Before registering a trademark or preparing print masters, have a designer make final optical adjustments.
