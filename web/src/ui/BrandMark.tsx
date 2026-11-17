/**
 * Mandatary identity marker for the shared headers (P1.20.1).
 *
 * Source of truth: the approved artwork in web/brand/ (mandatary-icon.svg, mandatary-icon-light.svg). The path
 * data below is a verbatim copy of that artwork and BrandMark.test.tsx fails if either drifts. Why an inline
 * <svg> and not an <img src>: the document CSP is `img-src 'self'` with no data: URIs, and Vite would inline a
 * small .svg as a data: URI, which the policy blocks; inline elements also let the colours follow the same
 * `data-theme` tokens as the rest of the page, so the mark can never be a different theme from its surroundings
 * (no wrong-theme flash, no second request, no JavaScript branch on the theme).
 *
 * Wordmark: the approved wordmark is Manrope 800, but the CSP serves no web fonts (`font-src` falls back to
 * `default-src 'none'`), so the header wordmark is live text in the application's system font stack, weight and
 * tracking matched to the artwork. The full-logo SVGs (which carry the tagline and live Manrope text) are kept as
 * source assets only and are not used at runtime.
 *
 * Accessibility: the glyph is decorative (aria-hidden); the lowercase word beside it is the single accessible
 * name, so a screen reader announces "mandatary" once. It is not a link and not a landmark: it is an identity
 * marker, not navigation.
 */

/** Verbatim from web/brand/mandatary-icon.svg (identical in the light variant); 512x512 artwork space. */
export const ICON_PATHS = {
  gateway: 'M256 42 454 146V365l-49-27V176L256 100 107 176v162l-49 27V146Z',
  pillarLeft: 'm58 383 49-27v91l-49 23Z',
  pillarRight: 'm405 356 49 27v87l-49-23Z',
  m: 'm137 206 119 84 119-84v227l-49-25V301l-70 49-70-49v107l-49 25Z',
} as const;

/** Tight box around the artwork (x 58–454, y 42–470) so the CSS height is the glyph height. Geometry is unchanged. */
const GLYPH_VIEW_BOX = '58 42 396 428';

/** The gateway icon alone. Decorative: pair it with visible or screen-reader text. */
export function BrandIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox={GLYPH_VIEW_BOX} aria-hidden="true" focusable="false" className={className}>
      <path className="fill-brand-gateway" d={ICON_PATHS.gateway} />
      <path className="fill-brand-pillar" d={ICON_PATHS.pillarLeft} />
      <path className="fill-brand-pillar" d={ICON_PATHS.pillarRight} />
      <path className="fill-brand-mark" d={ICON_PATHS.m} />
    </svg>
  );
}

export type BrandSize = 'header' | 'frame';

function sizeClasses(size: BrandSize): { icon: string; word: string } {
  // Shell header: the quietest treatment (24 px glyph, 16 px bold wordmark), inside the 56/64 px bar it lives in.
  if (size === 'header') return { icon: 'h-6 aspect-[396/428]', word: 'text-base' };
  // Pre-session top bar: the same mark, 4 px taller, because nothing else competes with it there. Below 350 px the
  // long theme-toggle label leaves no room, so only the glyph shows; the word stays as the accessible name.
  return { icon: 'h-7 aspect-[396/428]', word: 'text-[1.0625rem] max-[350px]:sr-only' };
}

/** Icon + lowercase wordmark, no tagline. One accessible name ("mandatary"); the glyph is hidden from assistive tech. */
export function BrandLockup({ size = 'header' }: { size?: BrandSize }) {
  const { icon, word } = sizeClasses(size);
  return (
    <p className="flex items-center gap-2.5">
      <BrandIcon className={`shrink-0 ${icon}`} />
      <span className={`font-bold leading-none tracking-[-0.03em] text-brand-wordmark ${word}`}>mandatary</span>
    </p>
  );
}
