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
  /** Really unavailable (a form that is being sent): not focusable until it is back. */
  disabled?: boolean;
  /** Leading icon. */
  icon?: IconName;
  children: ReactNode;
}

/** Primary is ink, quiet is an ink outline, danger is a flare outline. Colour is never brand. */
export function Button(
  {
    variant = "quiet",
    testId,
    onClick,
    type = "button",
    block = false,
    disabled = false,
    icon,
    children,
  }: ButtonProps,
) {
  return (
    <button
      type={type}
      className={`btn btn--${variant}${block ? " btn--block" : ""}`}
      data-testid={testId}
      disabled={disabled}
      onClick={onClick}
    >
      {icon && <Icon name={icon} />}
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
  /** A toggle that is on (`aria-pressed`). Omit for a plain button. */
  pressed?: boolean;
  /** Extra class names (the call controls style theirs). */
  className?: string;
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
      className={`icon-btn${props.filled ? " icon-btn--filled" : ""}${
        props.className ? ` ${props.className}` : ""
      }`}
      aria-label={props.label}
      aria-pressed={props.pressed === undefined ? undefined : props.pressed ? "true" : "false"}
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
