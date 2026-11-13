export interface SkeletonProps {
  /** What is loading, e.g. "addresses". Announced as "Loading addresses…". */
  label: string;
  /** Placeholder line count. Defaults to 3; clamped to 1–10. */
  lines?: number;
}

const DEFAULT_LINES = 3;
const MIN_LINES = 1;
const MAX_LINES = 10;

function clampLines(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return DEFAULT_LINES;
  return Math.min(MAX_LINES, Math.max(MIN_LINES, Math.trunc(value)));
}

/**
 * Loading placeholder (UX §9): a visible, polite status line plus blocks the screen reader skips.
 * Shimmer runs only under the `motion-safe` variant, so reduced motion gets static blocks. Each
 * line is a fixed height so the layout does not jump when the content arrives.
 */
export function Skeleton({ label, lines }: SkeletonProps) {
  const count = clampLines(lines);
  return (
    <div role="status" aria-busy="true" className="space-y-3 py-1">
      <p className="text-sm text-muted">{`Loading ${label}…`}</p>
      <div aria-hidden="true" className="space-y-2">
        {Array.from({ length: count }, (_, index) => (
          <div key={index} data-skeleton-line className={`h-4 rounded-control bg-sunken motion-safe:animate-pulse ${index === count - 1 && count > 1 ? 'w-2/3' : 'w-full'}`} />
        ))}
      </div>
    </div>
  );
}
