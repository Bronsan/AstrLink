import {
  Fragment,
  useEffect,
  useMemo,
  useRef,
  type KeyboardEvent,
  type ReactNode,
  type Ref,
  type RefObject,
} from "react";

import { ChevronDown, ChevronUp, Search, X } from "@/components/icons";
import { IconButton } from "@/components/IconButton";
import { Input } from "@/components/ui/input";
import {
  FIND_HIT_LIMIT,
  findMatcher,
  findOffsets,
  type FindResult,
} from "@/find-model";
import { useT } from "@/i18n";
import { cn } from "@/lib/utils";

/**
 * One compact find row: the query, where the reader is among the hits, and
 * the steps between them. Enter moves to the next hit, Shift+Enter to the
 * previous one, and Escape closes the row.
 */
export function FindBar({
  query,
  onQueryChange,
  result,
  active,
  onStep,
  onClose,
  label,
  placeholder,
  inputRef,
  className,
}: {
  query: string;
  onQueryChange: (query: string) => void;
  /** Hits for the query; null while the view is still searching. */
  result: FindResult | null;
  /** Zero-based hit in view. */
  active: number;
  onStep: (step: 1 | -1) => void;
  onClose: () => void;
  label: string;
  placeholder: string;
  inputRef?: Ref<HTMLInputElement>;
  className?: string;
}) {
  const t = useT();
  const blank = query.trim() === "";
  const count = result?.count ?? 0;
  const status = blank
    ? ""
    : result === null
      ? "…"
      : count === 0
        ? t("find.none")
        : `${Math.min(active, count - 1) + 1}/${count}${result.capped ? "+" : ""}`;
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      if (count > 0) onStep(event.shiftKey ? -1 : 1);
    } else if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onClose();
    }
  };
  return (
    <div
      className={cn("flex min-w-0 items-center gap-0.5", className)}
      data-testid="find-bar"
      role="search"
    >
      <span className="relative flex min-w-0 flex-1 items-center">
        <Search
          animateOnHover={false}
          aria-hidden="true"
          className="pointer-events-none absolute left-2 size-3.5 text-muted-foreground"
        />
        <Input
          aria-label={label}
          autoFocus
          className="h-6 rounded-sm pr-1.5 pl-7 text-xs"
          data-testid="find-input"
          onChange={(event) => onQueryChange(event.currentTarget.value)}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          ref={inputRef}
          spellCheck={false}
          value={query}
        />
      </span>
      <span
        aria-live="polite"
        className={cn(
          "min-w-9 shrink-0 px-1 text-center font-mono text-micro tabular-nums text-muted-foreground",
          !blank && result?.count === 0 && "text-warning-foreground",
        )}
        data-testid="find-count"
      >
        {status}
      </span>
      <IconButton
        disabled={count === 0}
        label={t("find.previous")}
        onClick={() => onStep(-1)}
        size="icon-xs"
        type="button"
      >
        <ChevronUp aria-hidden="true" />
      </IconButton>
      <IconButton
        disabled={count === 0}
        label={t("find.next")}
        onClick={() => onStep(1)}
        size="icon-xs"
        type="button"
      >
        <ChevronDown aria-hidden="true" />
      </IconButton>
      <IconButton
        label={t("find.close")}
        onClick={onClose}
        size="icon-xs"
        type="button"
      >
        <X aria-hidden="true" />
      </IconButton>
    </div>
  );
}

/** A find hit; the one in view is filled so it stands out from the rest. */
export function FindMark({
  active = false,
  children,
}: {
  active?: boolean;
  children: ReactNode;
}) {
  return (
    <mark
      className={cn(
        "rounded-sm text-inherit",
        active
          ? "bg-primary-fill text-primary-fill-foreground ring-2 ring-tide/40"
          : "bg-tide/25",
      )}
      data-find-active={active ? "true" : undefined}
      data-testid="find-mark"
    >
      {children}
    </mark>
  );
}

function plainText(text: string): ReactNode {
  return text;
}

/**
 * `text` with a mark at each offset. The gaps still go through `renderText`,
 * so other highlighting, such as privacy placeholders, survives around hits.
 */
export function markText(
  text: string,
  offsets: readonly number[] | undefined,
  length: number,
  activeOffset: number | null = null,
  renderText: (text: string) => ReactNode = plainText,
): ReactNode {
  if (!offsets || offsets.length === 0 || length <= 0) return renderText(text);
  const parts: ReactNode[] = [];
  let cursor = 0;
  for (const offset of offsets) {
    if (offset < cursor || offset >= text.length) continue;
    if (offset > cursor) {
      parts.push(
        <Fragment key={`text-${cursor}`}>
          {renderText(text.slice(cursor, offset))}
        </Fragment>,
      );
    }
    const end = Math.min(text.length, offset + length);
    parts.push(
      <FindMark active={offset === activeOffset} key={`hit-${offset}`}>
        {text.slice(offset, end)}
      </FindMark>,
    );
    cursor = end;
  }
  if (cursor < text.length) {
    parts.push(
      <Fragment key={`text-${cursor}`}>
        {renderText(text.slice(cursor))}
      </Fragment>,
    );
  }
  return parts;
}

/** Short text with every hit of `query` marked, for list rows and labels. */
export function HighlightedText({
  text,
  query,
}: {
  text: string;
  query?: string;
}) {
  const matcher = useMemo(() => (query ? findMatcher(query) : null), [query]);
  if (!matcher) return text;
  const offsets = findOffsets(text, matcher, FIND_HIT_LIMIT);
  return markText(text, offsets, query!.trim().length);
}

/**
 * Brings the active hit into view once it has rendered. A step may first
 * have to unfold or page the content, so the scroll waits for the commit in
 * which the active mark exists rather than firing with the step.
 */
export function useFindScroll(
  container: RefObject<HTMLElement | null>,
  target: unknown,
  seq: number,
): void {
  const pending = useRef(false);
  useEffect(() => {
    pending.current = target !== null && target !== undefined;
  }, [target, seq]);
  useEffect(() => {
    if (!pending.current) return;
    const root = container.current;
    const mark =
      root?.querySelector<HTMLElement>('mark[data-find-active="true"]') ??
      root?.querySelector<HTMLElement>('[data-find-active="true"]');
    if (!mark) return;
    pending.current = false;
    mark.scrollIntoView({ block: "center", inline: "nearest" });
  });
}
