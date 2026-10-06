import { type ReactNode, useEffect, useId, useState } from "react";
import { useT } from "../i18n";
import type { ServicePerformance, UsageStatus } from "../usage-range";
import type { PerformanceTarget } from "../use-performance-details";
import {
  TokensPerSecond,
  UsagePerformanceDetails,
} from "./UsagePerformanceDetails";
import { Activity } from "./icons";
import { DataField } from "./DataRow";
import { Button } from "./ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "./ui/popover";
import { cn } from "@/lib/utils";

export function UsagePerformanceMeter({
  performance,
  status,
  periodLabel,
  scopeDescription,
  target,
  ready,
  testId = "usage-performance",
  layout = "stacked",
}: {
  performance?: ServicePerformance;
  status: UsageStatus;
  periodLabel: string;
  scopeDescription: string;
  target: PerformanceTarget;
  ready: boolean;
  testId?: string;
  layout?: "stacked" | "fields" | "service";
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!ready) setOpen(false);
  }, [ready]);
  const titleId = useId();
  const valuesId = useId();
  const cache = performance?.cache_hit_rate;
  const speed = performance?.output_tokens_per_second;
  const placeholder = status === "loading" ? "…" : "—";
  const details = (trigger: ReactNode) => (
    <Popover open={open && ready} onOpenChange={setOpen}>
      <PopoverTrigger asChild>{trigger}</PopoverTrigger>
      <PopoverContent align="end" className="w-96" aria-labelledby={titleId}>
        <UsagePerformanceDetails
          target={target}
          open={open && ready}
          scopeDescription={scopeDescription}
          titleId={titleId}
        />
      </PopoverContent>
    </Popover>
  );
  const detailsLabel = t("services.performanceDetailsFor", {
    name: target.name,
  });
  if (layout === "fields") {
    return (
      <div
        className={cn(
          "col-span-2 row-span-2 grid grid-cols-2 grid-rows-subgrid gap-x-4 gap-y-1 tabular-nums",
          status === "error" && "row-span-3",
        )}
        data-testid={testId}
      >
        <DataField
          className="row-span-2 grid grid-rows-subgrid"
          label={t("services.cacheUtilization")}
          value={
            <span className="font-semibold">
              {cache == null ? placeholder : `${(cache * 100).toFixed(1)}%`}
            </span>
          }
        />
        <DataField
          className="row-span-2 grid grid-rows-subgrid"
          label="TPS"
          value={
            <span className="inline-flex items-center gap-1 font-semibold">
              <span>
                <TokensPerSecond value={speed} placeholder={placeholder} />
              </span>
              {details(
                <Button
                  aria-label={detailsLabel}
                  disabled={!ready}
                  size="icon-xs"
                  variant="ghost"
                  type="button"
                >
                  <Activity
                    aria-hidden="true"
                    className="text-muted-foreground"
                  />
                </Button>,
              )}
            </span>
          }
        />
        {status === "error" ? (
          <p className="col-span-2 text-micro text-muted-foreground">
            {t("services.performanceError")}
          </p>
        ) : null}
      </div>
    );
  }
  // The two values open the details themselves, like the billing amount next
  // to them; the range selector above the list already names the period.
  return details(
    <Button
      aria-describedby={valuesId}
      aria-label={detailsLabel}
      className={cn(
        "h-auto w-full justify-start px-0 text-left text-xs font-normal tabular-nums",
        layout === "service" && "w-fit @[640px]/service-list:w-full",
      )}
      data-testid={testId}
      disabled={!ready}
      size="xs"
      variant="ghost"
      type="button"
    >
      <span
        className={cn(
          "grid w-full gap-1",
          layout === "service" &&
            "flex flex-wrap items-center gap-x-3 @[640px]/service-list:grid @[640px]/service-list:gap-x-1",
        )}
        id={valuesId}
      >
        <span className="sr-only">{periodLabel}</span>
        {status === "error" ? (
          <span className="text-muted-foreground">
            {t("services.performanceError")}
          </span>
        ) : (
          <>
            <span className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground">
                {t("services.cacheUtilization")}
              </span>
              <span>
                {cache == null ? placeholder : `${(cache * 100).toFixed(1)}%`}
              </span>
            </span>
            <span className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground">TPS</span>
              <span>
                <TokensPerSecond value={speed} placeholder={placeholder} />
              </span>
            </span>
          </>
        )}
      </span>
    </Button>,
  );
}
