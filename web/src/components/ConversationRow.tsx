import { t } from "../i18n/index.ts";
import type { Contact } from "../state/model.ts";

/** The first letter of a name, for an avatar. */
export function initial(name: string): string {
  const first = [...name.trim()][0];
  return first ? first.toLocaleUpperCase() : "?";
}

export function Avatar({ contact, dot = false }: { contact: Contact; dot?: boolean }) {
  return (
    <span
      className={contact.kind === "group" ? "avatar avatar--group" : "avatar"}
      aria-hidden="true"
    >
      {initial(contact.name)}
      {dot && <span className="avatar__dot" />}
    </span>
  );
}

/** "{n} waiting": messages still on this device. Amber and dashed, like the bubbles it counts. */
export function WaitingChip({ count }: { count: number }) {
  return <span className="chip" data-testid="waiting-chip">{t("list.waiting", { n: count })}</span>;
}

export function SectionHeader({ children }: { children: string }) {
  return <h2 className="section-header">{children}</h2>;
}

export function ConversationRow({ contact, preview, waiting, href, current }: {
  contact: Contact;
  /** The last message, already in words. */
  preview: string;
  waiting: number;
  href: string;
  current: boolean;
}) {
  return (
    <a
      className="row"
      href={href}
      aria-current={current ? "page" : undefined}
      data-testid={`row-${contact.peerId.slice(0, 8)}`}
    >
      <Avatar contact={contact} dot={contact.path === "Direct"} />
      <span className="row__text">
        <span className="row__name">
          <bdi>{contact.name}</bdi>
        </span>
        <span className="row__preview">
          <bdi>{preview}</bdi>
        </span>
      </span>
      {waiting > 0 && <WaitingChip count={waiting} />}
    </a>
  );
}
