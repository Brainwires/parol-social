import type { ReactNode } from "denext";
import { Icon, type IconName } from "./Icon.tsx";

export type ButtonVariant = "primary" | "quiet" | "danger";

interface ButtonProps {
  variant?: ButtonVariant;
  /** Stable id for tests. */
  testId: string;
  onClick?: () => void;
  type?: "button" | "submit";
  block?: boolean;
  children: ReactNode;
}

/** Primary is ink, quiet is an ink outline, danger is a flare outline. Colour is never brand. */
export function Button(
  { variant = "quiet", testId, onClick, type = "button", block = false, children }: ButtonProps,
) {
  return (
    <button
      type={type}
      className={`btn btn--${variant}${block ? " btn--block" : ""}`}
      data-testid={testId}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

interface IconButtonProps {
  icon: IconName;
  /** The accessible name: what the button does. */
  label: string;
  testId: string;
  onClick?: () => void;
  type?: "button" | "submit";
  filled?: boolean;
  /**
   * Unavailable, but still focusable so it can say why: the click and focus handlers keep
   * running and the caller shows the reason (`describedBy` points at it).
   */
  unavailable?: boolean;
  describedBy?: string;
  onFocus?: () => void;
  onBlur?: () => void;
}

export function IconButton(props: IconButtonProps) {
  return (
    <button
      type={props.type ?? "button"}
      className={props.filled ? "icon-btn icon-btn--filled" : "icon-btn"}
      aria-label={props.label}
      aria-disabled={props.unavailable ? "true" : undefined}
      aria-describedby={props.describedBy}
      data-testid={props.testId}
      onClick={props.onClick}
      onFocus={props.onFocus}
      onBlur={props.onBlur}
    >
      <Icon name={props.icon} />
    </button>
  );
}
