import type { ReactNode } from "react";
import { motion, useReducedMotion } from "motion/react";

import { ArrowRight, X } from "@/components/icons";
import { IconButton } from "@/components/IconButton";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

/**
 * Point out an existing action without moving focus or changing its behavior.
 * `side` puts the message below an action that sits at the top edge, such as
 * one in the title bar.
 */
export function ActionHint({
  children,
  open,
  onDismiss,
  message,
  dismissLabel,
  side = "top",
}: {
  children: ReactNode;
  open: boolean;
  onDismiss: () => void;
  message: string;
  dismissLabel: string;
  side?: "top" | "bottom";
}) {
  const reducedMotion = useReducedMotion();
  // The action nods toward its message.
  const nod = side === "top" ? -4 : 4;
  return (
    <Popover open={open} onOpenChange={(next) => !next && onDismiss()}>
      <PopoverAnchor asChild>
        <motion.div
          className="shrink-0 rounded-md"
          initial={false}
          animate={{ y: open && !reducedMotion ? [0, nod, 0] : 0 }}
          transition={{ duration: 0.6, repeat: open ? 2 : 0, delay: 0.15 }}
        >
          {children}
        </motion.div>
      </PopoverAnchor>
      <PopoverContent
        side={side}
        align="end"
        hideWhenDetached
        role="status"
        aria-live="polite"
        className={cn(
          "flex w-64 items-start gap-2 p-3 text-xs leading-relaxed motion-safe:animate-in motion-safe:fade-in motion-safe:duration-300",
          side === "top"
            ? "motion-safe:slide-in-from-bottom-2"
            : "motion-safe:slide-in-from-top-2",
        )}
        onOpenAutoFocus={(event) => event.preventDefault()}
        onCloseAutoFocus={(event) => event.preventDefault()}
      >
        <ArrowRight
          aria-hidden="true"
          className={cn(
            "mt-0.5 size-4 shrink-0 text-primary",
            // Toward the action: below and right of a message above it.
            side === "top" ? "rotate-45" : "-rotate-45",
          )}
        />
        <p className="flex-1">{message}</p>
        <IconButton label={dismissLabel} size="icon-xs" onClick={onDismiss}>
          <X aria-hidden="true" />
        </IconButton>
      </PopoverContent>
    </Popover>
  );
}
