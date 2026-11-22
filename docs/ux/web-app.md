# ParolNet web app: design

This is the design of the web app (`web/`), and of the desktop app after it. It is decided;
implement it as written. The values live in one file, `web/src/design/tokens.json`: the web
app's CSS custom properties are generated from it (`web/scripts/gen-tokens.ts`) and the GPUI
desktop app reads the same JSON.

Every state described here can be seen and flipped in the app's state lab, `#/lab`
(development and test builds; the production export has no lab).

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
| `lamp` | `#8A5A00` | `#F0BC55` | Waiting or held, as text; the focus ring in the light theme |
| `lamp-line` | `#D9981E` | `#D9981E` | Waiting or held, as a line; the focus ring in the dark theme |
| `lamp-fill` | `#FBEFD3` | `#3A2E12` | Ground behind a waiting state |
| `flare` | `#B3261E` | `#FF8A80` | Blocked for safety, or destructive |
| `flare-fill` | `#F9DEDB` | `#44201D` | Ground behind a blocked state |
| `video-ground` | `#0B1216` | `#05090B` | Behind video |
| `on-video` | `#F3F5F4` | `#E8EEEC` | Words and controls over video |
| `flare-on-video` | `#FF8A80` | `#FF8A80` | The end-call control over video |

- **Theme**: follows the system; a person can override it (light, dark, system). The choice
  is kept on the device (`localStorage`, key `parolnet.theme`).
- **Type**: Atkinson Hyperlegible Next for everything; Atkinson Hyperlegible Mono for codes
  and safety numbers. Vazirmatn for Arabic and Farsi, loaded only for those locales; CJK uses
  the system's fonts. All fonts are self-hosted. Base size 17px, on a modular scale (ratio
  1.2: 14, 17, 20, 24, 29). Sentence case everywhere; no all-caps labels.
- **Radii**: 10px controls, 14px bubbles (4px on the tail corner), 12px panels, full for
  avatars and chips.
- **Focus ring**: 3px, 2px offset. `lamp` in the light theme (5.4:1 on `paper`), `lamp-line`
  in the dark theme and over video (7.2:1). It clears 3:1 on every ground a control sits on;
  `web/tests/unit/tokens.test.ts` checks that.
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
- **Composer**: never disabled because the contact is away. Placeholder "Message {name}" on an
  open line; "{name} is away. Your message will wait here." while waiting for them to come
  online; "Your message will wait here until a path exists." in every other state (connecting,
  no path, blocked, this device offline), where saying they are away would be untrue.
- **Unread badge**: the number of messages that arrived and were not read, in ink (it is not a
  state). The row's name is bold while there are any.
- **QR code**: this device's code as a picture, always dark on white with its quiet zone. At
  most 17rem wide: a real code (up to about 340 hex characters, with a relay address in it) is
  at most a version-15 code, 85 modules with the quiet zone, so a module is at least 3.2px.
- **Switch**: on or off; the thumb's side says which, not colour alone.
- **CodeBlock**: a pairing code in mono, grouped in fours (set smaller when it is long: a real
  code is a few hundred characters). Where it can be copied by hand, focusing or clicking it
  selects the whole code.
- **SafetyNumber**: 12 groups of 5 digits, mono.
- **Sheet / dialog**: focus is trapped inside, Escape closes, focus returns to what opened it.
- **Toast**: only to confirm something the person just did ("Message taken back"). It sits at
  the top, centred just under the header (under a conversation's two-row header on a phone;
  over the screen beside the list at wide widths), clear of the safe-area insets, so it never
  covers the composer, the call controls or a sheet's actions, which are all at the bottom. It
  is a polite live region, goes after four seconds, never takes focus and lets clicks through.

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

The header's avatar opens the contact's details: its name (only this device sees it), how it
was verified, and "Remove contact", which asks first. While a contact is not verified, one
line under the header says "Not verified yet" with "Compare safety numbers" beside it.

What could not be done (a message too long, a message that had already left) is said in a
line above the composer, in plain words, and the text stays in the field.

### Conversation list

One list for people and groups. "Online now" first, then "Away"; within each, by last activity,
newest first. Amber "{n} waiting" chips, and a count of unread messages. "Add a contact" is the
primary action. With no contacts, the list invites adding the first. The list also carries what
the app has to say on its own: "You are offline", "A new version is ready", a failed save, a
relay server that cannot be reached, and (once there is a contact, where the browser can
install the app) one unobtrusive line offering to install it. Once there is a contact and no
backup was ever made on the device, one more such line: "Make a backup, so that losing this
device does not lose your contacts." with [Back up] and [Not now].

### First run

"ParolNet" / "Private calls and messages, straight from your device to theirs." / "No account,
no phone number, no email. Nothing is stored on a server." / [Start]. Start makes this device's
identity and goes straight to "Add a contact". No name, no passphrase, no tour. No identity
is made and nothing is contacted before Start. Under Start, a quiet [Restore from a backup]:
the backup file, its passphrase, [Restore]; the app then starts as the person the backup
holds.

### Locked

With a passphrase set, every start shows "ParolNet is locked": one passphrase field,
[Unlock], and "Forgot your passphrase?". A wrong passphrase is said in words under the
field; from the third wrong try on, the next try has to wait, and the wait is counted down
("Too many wrong tries. Try again in 5 seconds."). "Forgot your passphrase?" says that it
cannot be recovered and offers the one thing left: delete everything on this device, after
typing "delete".

### Add a contact

One screen for both directions.

- **Your code**: as a QR code, "Good for {n} minutes. Works once." (the code's real
  lifetime), [Copy code] and, where the browser can, [Share]. The text of the code (a few
  hundred characters) is behind "Show the code as text", a disclosure that opens it in place
  as mono groups; Copy and Share work with it closed. Then "Keep this screen open while they
  add you." On a phone (390 by 800) the QR code, the lifetime, Copy, Share and the two ways to
  take theirs are all on the first screen, without scrolling.
- **Only while it is on screen.** Leaving "Add a contact" cancels the code being shown, so a
  code works only while its owner is looking at it. A new code is made when there is none:
  on arrival (so coming back shows a fresh one), after a reload, when one expires, and after
  one was used.
- **Theirs**: [Scan theirs] (the camera; it is released on leaving the screen and as soon as a
  code is read) or [Paste theirs].
- One sentence, not a dialog: "Contacts you add can see your IP address." with "Hide it",
  which leads to the relay-server setting.
- **Then a name.** Whoever was added, by either side, is given a name ("Only you see this
  name."). A scanned code means the two devices were together: that contact is verified in
  person. A pasted code, or someone using this device's code, is "Not verified yet".
- **A contact with no name** (someone used this device's code just as the person left the
  screen, or the person left the naming step) is "New contact" in the list. Its conversation
  asks once, in a line under the header that blocks nothing and takes no focus: "Someone used
  your code. Give them a name." (or "Give this contact a name." when this device added them),
  a name field, [Save] and "Not now", with "Not verified yet" under it as for a pasted code.
  "Not now" puts it away until the app is next opened.

Mistakes are said where they happen: an incomplete code, an expired one, one's own.

### Comparing safety numbers

A sheet: the safety number (12 groups of 5, mono), "Ask {name} to open this screen too, in
person or on a call where you know their voice. Read the numbers to each other.", then
[They match] (the contact is verified) or [They don't match] ("Do not trust this conversation
yet", why, and [Remove and add again], which removes the contact and opens "Add a contact").

### Calls

Call buttons are in the conversation header, enabled on an open line only.

| State | What the person sees |
| --- | --- |
| Outgoing | The call screen: "Calling {name}…", [End call] |
| Incoming | The whole screen on a phone, a banner at wide widths: "{name} is calling" (or "… with video"), [Accept] [Decline]. Focus goes to the words, never to a button |
| Connecting | "Connecting to {name}" |
| Active | Their video fills the window, this device's camera floats in a corner. "Direct, end-to-end encrypted" and a timer. Controls: microphone, camera (video calls), switch camera (more than one camera), audio output (where the browser can choose one), end call |
| Ended | The same screen says how, in plain words, for a few seconds or until [Close] |

How a call ended, per `CallEnd`: `HungUp` "Call ended"; `RemoteHungUp` "{name} ended the
call"; `Rejected` "{name} declined"; `NoAnswer` "{name} did not answer" (outgoing) or "Missed
call from {name}" (incoming); `Failed` "The call could not connect. Check that you are both
online, then call again.", or, when the microphone or camera could not be used, that and what
to allow. `Declined` (this device declined) shows nothing.

The call screen is on `video-ground` in both themes, with `on-video` words and controls. A
control that is switched on (muted, camera off) is filled and its icon is struck through.
Escape does not end a call. A tone made on the device rings, only once the person has
interacted with the page.

### Settings

Five plain groups.

- **You**: "Your code" (opens "Add a contact").
  "Lock ParolNet with a passphrase": two honest sentences on what encryption on the device
  does without one, then [Set a passphrase] (typed twice, at least 8 characters, and "If you
  forget this passphrase, nobody can recover it…"). Once set: [Lock now], [Change passphrase]
  and [Remove passphrase], the last two asking for the current one.
  "Back up this device": what a backup is and when the last one was made, then a sheet: a
  passphrase for the file (typed twice), "Include message history" (off), [Make the backup],
  and then a link, [Save the backup file], with "Use a backup on one device at a time: two
  devices with the same identity keep cutting each other off."
  "Restore from a backup": as on first run, and because it replaces what is on the device,
  the word "replace" is typed first.
  "Delete all data on this device", which asks for the word "delete" to be typed, then
  returns to first run.
- **Connection**: the connection in words; "Relay through my own TURN server" (address,
  username, password, "Use only this server", Save / Remove) with the IP sentence. A saved
  password is never shown back: the field is empty and says one is saved. Under "Advanced":
  the app's own server address (default: the server the app came from).
- **Calls and devices**: camera, microphone, speaker (remembered on this device); "Notify me
  while ParolNet is open".
- **Appearance and language**: theme (match device, light, dark) and language.
- **About**: version, licences, and one paragraph on what the app does and does not do
  ("ParolNet rings and receives only while it is open.").

### Open in another tab

ParolNet runs in one tab at a time. A second tab says "ParolNet is open in another tab" with
[Use it here]; the tab that had it stops and says "ParolNet moved to another tab".

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
  locale, loaded on demand. A key a locale lacks falls back to English, key by key; in a
  right-to-left locale that English is isolated as left-to-right text.
- What arrives while the person is elsewhere (a message, a call) is announced in a polite
  live region; focus is moved only by the person, by navigation, and by a sheet.
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
- The focus ring is `lamp` in the light theme (decided in review: `lamp-line` was 2.3:1 on
  `paper`, under the 3:1 a focus indicator needs). Dashed amber borders keep `lamp-line`:
  each has words or a shape beside it.
- "Add a contact" in the list's header is a filled "+" with that name: the worded button did
  not fit beside the title at the list's width in every language. The empty list keeps the
  worded button.
- The verification prompt is a line under the header, not a panel: a panel is for something
  that stops the conversation, and this does not.
- An incoming call takes focus to its words, not to Accept: a key pressed for something else
  must not answer a call.
- The unread count is in ink. It is a number, not a state.
- A contact that has no name yet is "New contact". The engine stores an empty name and the
  screens show "New contact", so the app can tell an unnamed contact from one named that.
- The text of the code is behind a disclosure on "Add a contact" (decided in review: the
  open block, eleven rows on a phone, pushed the other direction off the screen).
- Toasts moved from the bottom to the top (decided in review: one covered the composer).
- The naming prompt's "Not now" lasts until the app is next opened; nothing about it is
  stored.
- A contact that came out of a backup says so in a line under the conversation's header
  until a connection to it has held; if the connection fails its check, the red panel says
  that the backup is older than the conversation and offers "Remove contact", instead of the
  general explanation and "Try again", which could not help.
- "Lock now" and a restore reload the page. Nothing else would be honest: the keys must leave
  the page's memory, and a restored identity needs a fresh start.
- The backup's passphrase is asked for separately from the lock's, even when one is set: the
  file leaves the device and may be kept for years.
