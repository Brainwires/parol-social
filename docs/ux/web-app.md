# ParolNet web app: design

This is the design of the web app (`web/`), and of the desktop app after it. It is decided;
implement it as written. The values live in one file, `web/src/design/tokens.json`: the web
app's CSS custom properties are generated from it (`web/scripts/gen-tokens.ts`) and the GPUI
desktop app reads the same JSON.

Every state described here can be seen and flipped in the app's state lab, `#/lab`.

## The idea

ParolNet has no server that holds messages. A message is in one of two places: on your
device, or on theirs. The interface always shows which.

## Rules

1. **Outlined is here, filled is there.** A message that is still on your device is drawn as
   an outline. Once it is on their device it is filled. Text, files and call invitations all
   use this one form.
2. **One status line per conversation.** "The line" says, in words, what stands between you
   and the other person. It replaces banners, toasts and badges.
3. **Colour means state and nothing else.** Green: the direct line is open. Amber: waiting or
   held. Red: blocked for safety, or destructive. Buttons, bubbles and branding stay in ink.
   A state is never colour alone: each has its own line style and its own words.
4. **Never retry silently.** When something does not work, say why and offer the one or two
   things that fix it.
5. **Plain words.** People add a contact with a code. "Peer", "bootstrap", "ICE" and "relay"
   do not appear in the primary interface. ("Relay server" appears once, where a person
   chooses to use their own.)

## Tokens

Colours, light / dark:

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `paper` | `#F3F5F4` | `#0F181D` | Page ground |
| `surface` | `#FFFFFF` | `#172229` | Raised ground: sheets, fields |
| `fog` | `#E1E6E4` | `#26343C` | Lines, received bubbles |
| `ink` | `#15232D` | `#E8EEEC` | Text, delivered bubbles, primary buttons |
| `ink-2` | `#51606A` | `#9DACB3` | Secondary text |
| `on-ink` | `#F3F5F4` | `#0F181D` | Text on ink |
| `open` | `#0F7A5C` | `#5FD0AC` | The direct line is open |
| `open-fill` | `#D5EFE6` | `#12382F` | Ground behind an open state |
| `lamp` | `#8A5A00` | `#F0BC55` | Waiting or held, as text |
| `lamp-line` | `#D9981E` | `#D9981E` | Waiting or held, as a line; the focus ring |
| `lamp-fill` | `#FBEFD3` | `#3A2E12` | Ground behind a waiting state |
| `flare` | `#B3261E` | `#FF8A80` | Blocked for safety, or destructive |
| `flare-fill` | `#F9DEDB` | `#44201D` | Ground behind a blocked state |
| `video-ground` | `#0B1216` | `#05090B` | Behind video |

- **Theme**: follows the system; a person can override it (light, dark, system). The choice
  is kept on the device (`localStorage`, key `parolnet.theme`).
- **Type**: Atkinson Hyperlegible Next for everything; Atkinson Hyperlegible Mono for codes
  and safety numbers. Vazirmatn for Arabic and Farsi, loaded only for those locales; CJK uses
  the system's fonts. All fonts are self-hosted. Base size 17px, on a modular scale (ratio
  1.2: 14, 17, 20, 24, 29). Sentence case everywhere; no all-caps labels.
- **Radii**: 10px controls, 14px bubbles (4px on the tail corner), 12px panels, full for
  avatars and chips.
- **Focus ring**: 3px `lamp-line`, 2px offset.
- **Targets**: at least 44px.
- **Motion**: exactly one animated moment. When a contact comes online, their waiting
  messages fill in, in order, about 350ms apart, each with a 450ms fill. Everything else
  changes without animation, and `prefers-reduced-motion` turns even that off.

## The line

Two end dots and a wire, then words. The near end (at the start of the line) is this device,
the far end is theirs. It is an `aria-live="polite"` status.

| State | Wire | Ends | Words | Core state |
| --- | --- | --- | --- | --- |
| open | solid, green | both filled | Direct, end-to-end encrypted | `PathState::Direct` |
| waiting | dashed, amber | far end hollow | Waiting for {name} to come online | `Offline`, `Unknown` |
| connecting | dashed, amber | both filled | Connecting to {name} | `Connecting` |
| no path | dashed, amber, broken in the middle | both filled | No direct path to {name} | `NoDirectPath` |
| blocked | dotted, red | both filled | Blocked for your safety | `BindingFailed` |
| you are offline | dashed, amber | near end hollow | You are offline | no network or no relay (`RelayState::Disconnected`) |

Being offline yourself wins over every other state: nothing else can be known then.

## Components

- **Button**: primary (ink fill), quiet (ink outline), danger (flare outline).
- **IconButton**: always has an accessible name. When what it does is unavailable it stays
  focusable and says why.
- **Bubble**: received is a fog fill. Sent and delivered is an ink fill. Sent and held is
  transparent with a 1.5px dashed `lamp-line` border. One caption sits under the last of your
  messages: "Waiting on this device" in `lamp`, or "On {name}'s device" in `ink-2`. A message
  the queue had to drop (`DeliveryState::Dropped`) is a dotted `flare` outline with the
  caption "Not sent. Too many messages were waiting."
- **Held message menu**: a waiting message opens a menu with "Take back" and "Edit".
- **Panel**: amber or red, with a title, a body and at most two actions. (A plain, ink-outline
  panel carries the one notice that is neither: "A new version is ready".)
- **Conversation row**: avatar with the name's initial, a presence dot in `open` when the
  line is open, the name, a preview of the last message, and an amber dashed chip
  "{n} waiting" while messages for that contact are still on this device.
- **Section header**: "Online now", "Away".
- **Composer**: never disabled because the contact is away. Placeholder "Message {name}", or
  "{name} is away. Your message will wait here."
- **CodeBlock**: a pairing code in mono, grouped in fours.
- **SafetyNumber**: 12 groups of 5 digits, mono.
- **Sheet / dialog**: focus is trapped inside, Escape closes, focus returns to what opened it.
- **Toast**: only to confirm something the person just did ("Message taken back").

## Screens

### Conversation

| Line | What the person sees | What they can do |
| --- | --- | --- |
| open | Messages filled; "On {name}'s device" | Write, call |
| waiting | Held messages outlined; "Waiting on this device" | Write (it waits), take back or edit a held message |
| connecting | As waiting | Write (it waits) |
| no path | Amber panel: "Your two networks will not connect directly." / "This happens on some mobile and office networks. Your messages are safe on this device and will send as soon as a path exists." | "Try again", "Use my own relay server" |
| blocked | Red panel: "This connection did not pass its security check." / "Something between you and {name} changed the connection while it was being set up. ParolNet closed it. Nothing was sent." | "Try again", "What this means" |
| you are offline | As waiting, with the line "You are offline" | Write (it waits) |

Call buttons are enabled only on an open line. Otherwise they explain why on focus or tap:
"Calls need {name} online" (or "Calls need a direct line to {name}" when they are online but
unreachable, "Calls need you online" when this device is offline).

### Conversation list

One list for people and groups. "Online now" first, then "Away". Amber "{n} waiting" chips.
"Add a contact" is the primary action. With no contacts, the list invites adding the first.

### Layout

A phone shows one column with stack navigation: the list, then a conversation, with a way
back. From 900px wide, the list and the conversation sit side by side.

## Accessibility and languages

- WCAG 2.2 AA contrast in both themes; `web/tests/unit/tokens.test.ts` checks every pair of
  tokens the components put together.
- Everything works from the keyboard.
- Logical CSS properties only (no left or right), so `dir="rtl"` mirrors everything,
  including the line and the bubbles. Codes and safety numbers always run left to right.
  What a person wrote keeps the direction of its own script.
- Messages come from a catalogue with ICU-style placeholders and plurals, one JSON file per
  locale, loaded on demand.
- Every interactive control has a stable `data-testid`.

## Decisions made while building (for review)

These were not in the brief; each is the smallest reading that keeps the rules.

- `PathState::Unknown` shows the waiting line. Messages are held either way.
- "Online now" lists every contact the relay reaches (`Connecting`, `Direct`, `NoDirectPath`,
  `BindingFailed`); the green presence dot shows only on an open line, because green means
  the direct line is open and nothing else.
- The caption follows the last of your messages, not the last message of the thread.
- While the waiting messages fill in, the caption keeps saying "Waiting on this device" until
  the last one has filled.
- An unavailable call button is struck through as well as dimmed (state is never colour alone).
- Bubbles show no timestamps yet. The design does not place them.

## Open question: the focus ring in the light theme

`lamp-line` (`#D9981E`) on `paper` is 2.27:1 in the light theme (2.48:1 on `surface`). In the
dark theme it is 7.2:1. WCAG 1.4.11 asks 3:1 for a focus indicator, so the decided ring does
not meet it on light grounds. Dashed amber borders have words or a shape beside them and do
not depend on it; the focus ring does. Options: a darker `lamp-line` in light (for example
`lamp`, `#8A5A00`, 5.4:1), or a two-tone ring (`lamp-line` with an `ink` edge). The unit test
pins the current ratio so a change shows up.
