# Mandatary brand assets

Approved artwork and colour specification, versioned with the application so no build or runtime step reads
anything outside the repository. `THEME.md` and the four SVG files are **verbatim copies** of the owner-approved
set (`mandatary-logo/` supplied for P1.20.1); do not edit them in place. A new revision of the artwork replaces
them wholesale, and `src/ui/BrandMark.test.tsx` then shows what else must follow.

| File | Use |
|---|---|
| `THEME.md` | Approved element colours for the dark and light logo. |
| `mandatary-icon.svg`, `mandatary-icon-light.svg` | Gateway icon for dark / light surfaces. **Geometry source** of `src/ui/BrandMark.tsx`. |
| `mandatary-logo.svg`, `mandatary-logo-light.svg` | Full logo: icon, wordmark and tagline *Authority by design.* Source assets for documents and marketing; **not used at runtime**. |

The two `Branding-Overview-*.png` reference boards that came with the set are deliberately not copied (about
3 MB, no build or test depends on them).

## How the application header uses them

- `src/ui/BrandMark.tsx` draws the icon as an **inline SVG** with the same path data and the lowercase word
  `mandatary` beside it, without the tagline. It appears once per shared header (`AdminShell`, `CenteredFrame`). In the `CenteredFrame` bar the word is visually hidden below 350 px wide (it remains the accessible name).
- Inline, not `<img>`: the document CSP is `img-src 'self'` with no `data:` URIs, and the bundler would turn a
  small SVG into a `data:` URI. Inline elements also take their colours from the theme tokens, so the mark is
  always the same theme as the page.
- Colours are the `--brand-*` tokens in `src/style.css` (`--brand-mark`, `--brand-gateway`, `--brand-pillar`,
  `--brand-wordmark`), set per `data-theme` to the values in `THEME.md`. Gateway and pillars are the same in both
  themes. `--brand-tagline` is not defined because the tagline is not shown in the application.
- Brand colours are identity only. Text, controls and status keep their own semantic tokens (`--accent`,
  `--danger`, `--warn`, `--success`), whose contrast is asserted in `src/theme-contrast.test.ts`.
- **Wordmark font.** The artwork's wordmark is Manrope 800 as live SVG text with an `Inter, Arial, sans-serif`
  fallback. The application serves no web fonts (`font-src` falls back to `default-src 'none'`), so the header
  wordmark is live text in the system font stack with weight and tracking matched to the artwork, and the full-logo
  SVGs would render in a fallback font if embedded as-is. Exact Manrope rendering in the product would need an
  owner decision on shipping the (OFL-licensed) font or converting the wordmark to outlines; it is not done here.
- The SVGs are inert (no script, style, event handler, link, image, `foreignObject` or external reference); the
  test suite asserts it for all four.

## Integrity of the supplied set

SHA-256 of the verbatim copies (recorded when they were imported; they match the supplied files byte for byte):

```
102cbf24f13efa6f4e5d510217a645fe4eb60335559e5f881c6530d717c5f0c2  THEME.md
1d1da304dddb8279e4cb2748a9e593c4aa1fc63308e26fe2124c8db84d1d3f08  mandatary-icon.svg
66d27ac8d9be2dfd6ffa3345a841c7b22a0f8f48f1f0baaaec458efed8a02509  mandatary-icon-light.svg
12885318ed574b7a59ef6c0d4ee2d1341c912059404542b913fcb9a45c104740  mandatary-logo.svg
bb1bc85cdbc23e1baef0d69d94514f804c9262396de508c63f995667f71f8835  mandatary-logo-light.svg
```
