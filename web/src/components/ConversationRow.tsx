import { t } from "../i18n/index.ts";
import type { ContactView } from "../state/model.ts";

/** The first letter of a name, for an avatar. */
export function initial(name: string): string {
  const first = [...name.trim()][0];
  return first ? first.toLocaleUpperCase() : "?";
}

export function Avatar({ name, dot = false }: { name: string; dot?: boolean }) {
  return (
    <span className="avatar" aria-hidden="true">
      {initial(name)}
      {dot && <span className="avatar__dot" />}
    </span>
  );
}

/** "{n} waiting": messages still on this device. Amber and dashed, like the bubbles it counts. */
export function WaitingChip({ count }: { count: number }) {
  return <span className="chip" data-testid="waiting-chip">{t("list.waiting", { n: count })}</span>;
}

/** How many messages arrived and have not been read: ink, like everything that is not state. */
export function UnreadBadge({ count }: { count: number }) {
  return (
    <span className="badge" data-testid="unread-badge">
      <span aria-hidden="true">{count > 99 ? "99+" : count}</span>
      <span className="visually-hidden">{t("list.unread", { n: count })}</span>
    </span>
  );
}

export function SectionHeader({ children }: { children: string }) {
  return <h2 className="section-header">{children}</h2>;
}

export function ConversationRow({ view, preview, href, current }: {
  view: ContactView;
  /** The last message, already in words. */
  preview: string;
  href: string;
  current: boolean;
}) {
  const { contact } = view;
  return (
    <a
      className={view.unread > 0 ? "row row--unread" : "row"}
      href={href}
      aria-current={current ? "page" : undefined}
      data-testid={`row-${contact.peerId.slice(0, 8)}`}
    >
      <Avatar name={contact.name} dot={view.path === "Direct"} />
      <span className="row__text">
        <span className="row__name">
          <bdi>{contact.name}</bdi>
        </span>
        <span className="row__preview">
          <bdi>{preview}</bdi>
        </span>
      </span>
      {view.queued > 0 && <WaitingChip count={view.queued} />}
      {view.unread > 0 && <UnreadBadge count={view.unread} />}
    </a>
  );
}
