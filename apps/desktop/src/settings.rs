//! Settings: "Relay through my own TURN server".
//!
//! ParolNet has no TURN server of its own and never uses one a relay announces. A user who
//! wants to hide their IP address from contacts enters a TURN server they run or rent; the
//! core (`parolnet-app`) stores it and applies it to new connections at once. This view is
//! the form for it. The saved password never comes back into the form: an empty password
//! field on save keeps the stored one.

use gpui::{Context, Entity, FontWeight, IntoElement, Render, Window, div, prelude::*, px, rgb};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::checkbox::Checkbox;
use gpui_component::input::{Input, InputState};
use parolnet_app::{AppHandle, TurnSettings};

/// The one-line notice next to anything that sets up direct connections.
pub const IP_NOTICE: &str = "Direct connections show your contacts your IP address.";

/// The settings a form's fields describe, or what to tell the user is wrong with them.
/// `stored_password` is used when the password field was left empty.
pub fn turn_from_form(
    uri: &str,
    username: &str,
    password: &str,
    stored_password: Option<&str>,
    relay_only: bool,
) -> Result<TurnSettings, String> {
    if uri.trim().is_empty() {
        return Err("Enter your TURN server's address, like turn:turn.example.org:3478.".into());
    }
    let password = if password.is_empty() {
        stored_password.unwrap_or_default()
    } else {
        password
    };
    TurnSettings {
        uri: uri.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        relay_only,
    }
    .validated()
    .map_err(|e| match e {
        parolnet_app::AppError::Config(why) => why,
        other => other.to_string(),
    })
}

/// The line that says what is in effect: `saved` is the stored server's URI and whether
/// relay-only is on.
pub fn turn_status_text(saved: Option<(&str, bool)>) -> String {
    match saved {
        None => "No TURN server set: connections are direct.".to_owned(),
        Some((uri, true)) => format!(
            "Every connection is relayed through {uri}. Contacts see that server's address, \
             not yours."
        ),
        Some((uri, false)) => format!(
            "Connections are direct when possible; {uri} is used when there is no direct path."
        ),
    }
}

pub struct SettingsView {
    app: AppHandle,
    uri_input: Entity<InputState>,
    user_input: Entity<InputState>,
    password_input: Entity<InputState>,
    relay_only: bool,
    /// The stored server's URI and relay-only flag.
    saved: Option<(String, bool)>,
    /// The last result: text, and whether it is an error.
    message: Option<(String, bool)>,
}

impl SettingsView {
    pub fn new(app: AppHandle, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let uri_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("turn:turn.example.org:3478"));
        let user_input = cx.new(|cx| InputState::new(window, cx).placeholder("Username"));
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder("Password")
        });

        // Fill the form from what is stored (never the password).
        let app2 = app.clone();
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Some(stored)) = app2.turn_settings().await else {
                return;
            };
            let (uri, username, relay_only) = (
                stored.uri.clone(),
                stored.username.clone(),
                stored.relay_only,
            );
            drop(stored);
            let _ = this.update_in(cx, |view, window, cx| {
                view.uri_input
                    .update(cx, |s, cx| s.set_value(uri.clone(), window, cx));
                view.user_input
                    .update(cx, |s, cx| s.set_value(username, window, cx));
                view.relay_only = relay_only;
                view.saved = Some((uri, relay_only));
                cx.notify();
            });
        })
        .detach();

        SettingsView {
            app,
            uri_input,
            user_input,
            password_input,
            relay_only: false,
            saved: None,
            message: None,
        }
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let uri = self.uri_input.read(cx).value().to_string();
        let username = self.user_input.read(cx).value().to_string();
        let password = self.password_input.read(cx).value().to_string();
        let relay_only = self.relay_only;
        let app = self.app.clone();
        cx.spawn_in(window, async move |this, cx| {
            // An empty password field keeps the stored password.
            let stored = if password.is_empty() {
                app.turn_settings().await.ok().flatten()
            } else {
                None
            };
            let form = turn_from_form(
                &uri,
                &username,
                &password,
                stored.as_ref().map(|s| s.password.as_str()),
                relay_only,
            );
            drop(stored);
            let result = match form {
                Ok(settings) => {
                    let uri = settings.uri.clone();
                    app.set_turn_settings(settings)
                        .await
                        .map(|()| uri)
                        .map_err(|e| e.to_string())
                }
                Err(why) => Err(why),
            };
            let _ = this.update_in(cx, |view, window, cx| {
                match result {
                    Ok(uri) => {
                        view.password_input
                            .update(cx, |s, cx| s.set_value("", window, cx));
                        view.saved = Some((uri, relay_only));
                        view.message = Some(("Saved. New connections use it now.".into(), false));
                    }
                    Err(why) => view.message = Some((why, true)),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let app = self.app.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = app.clear_turn_settings().await;
            let _ = this.update_in(cx, |view, window, cx| {
                match result {
                    Ok(()) => {
                        for input in [&view.uri_input, &view.user_input, &view.password_input] {
                            input.update(cx, |s, cx| s.set_value("", window, cx));
                        }
                        view.relay_only = false;
                        view.saved = None;
                        view.message =
                            Some(("Removed. Connections are direct again.".into(), false));
                    }
                    Err(e) => view.message = Some((e.to_string(), true)),
                }
                cx.notify();
            });
        })
        .detach();
    }
}

fn muted(text: impl Into<gpui::SharedString>) -> impl IntoElement {
    div()
        .max_w(px(560.))
        .text_sm()
        .text_color(rgb(0x8b949e))
        .child(text.into())
}

impl Render for SettingsView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let saved = self.saved.as_ref().map(|(uri, only)| (uri.as_str(), *only));
        let mut form = div()
            .flex()
            .flex_col()
            .gap_2()
            .max_w(px(560.))
            .child(Input::new(&self.uri_input))
            .child(Input::new(&self.user_input))
            .child(Input::new(&self.password_input).mask_toggle())
            .child(
                Checkbox::new("relay-only")
                    .label("Use only this server (hide my IP address from contacts)")
                    .checked(self.relay_only)
                    .on_click(cx.listener(|this, checked: &bool, _, cx| {
                        this.relay_only = *checked;
                        cx.notify();
                    })),
            );
        if saved.is_some() {
            form = form.child(muted(
                "A password is saved. Leave the field empty to keep it.",
            ));
        }
        let mut buttons = div().flex().gap_2().child(
            Button::new("save-turn")
                .label("Save")
                .primary()
                .on_click(cx.listener(|this, _, window, cx| this.save(window, cx))),
        );
        if saved.is_some() {
            buttons = buttons.child(
                Button::new("clear-turn")
                    .label("Remove")
                    .on_click(cx.listener(|this, _, window, cx| this.clear(window, cx))),
            );
        }
        let mut page = div()
            .id("settings")
            .size_full()
            .overflow_y_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::BOLD)
                    .text_color(rgb(0xe6edf3))
                    .child("Relay through my own TURN server"),
            )
            .child(
                div()
                    .max_w(px(560.))
                    .text_sm()
                    .text_color(rgb(0xd29922))
                    .child(IP_NOTICE),
            )
            .child(muted(
                "Only contacts you connect to see it, never strangers. To hide it from them \
                 too, enter a TURN server you run or rent: your connections then go through \
                 it. ParolNet has no TURN server of its own and never uses one a relay \
                 offers. UDP only for now (turn:host:port).",
            ))
            .child(form)
            .child(buttons)
            .child(
                div()
                    .max_w(px(560.))
                    .text_sm()
                    .text_color(rgb(0xe6edf3))
                    .child(turn_status_text(saved)),
            );
        if let Some((text, is_error)) = &self.message {
            page = page.child(
                div()
                    .max_w(px(560.))
                    .text_sm()
                    .text_color(rgb(if *is_error { 0xffa198 } else { 0x3fb950 }))
                    .child(text.clone()),
            );
        }
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_form_becomes_settings() {
        let s = turn_from_form(
            " turn:turn.example.org:3478 ",
            " pat ",
            "secret",
            None,
            true,
        )
        .unwrap();
        assert_eq!(s.uri, "turn:turn.example.org:3478");
        assert_eq!(s.username, "pat");
        assert_eq!(s.password, "secret");
        assert!(s.relay_only);
        // The password is taken as typed, spaces included.
        let s = turn_from_form("turn:h", "pat", " a b ", None, false).unwrap();
        assert_eq!(s.password, " a b ");
        assert!(!s.relay_only);
    }

    #[test]
    fn an_empty_password_field_keeps_the_stored_password() {
        let s = turn_from_form("turn:h", "pat", "", Some("stored"), true).unwrap();
        assert_eq!(s.password, "stored");
        let s = turn_from_form("turn:h", "pat", "typed", Some("stored"), true).unwrap();
        assert_eq!(s.password, "typed");
        let err = turn_from_form("turn:h", "pat", "", None, true).unwrap_err();
        assert!(err.contains("password"), "{err}");
    }

    #[test]
    fn what_is_wrong_is_said_plainly_and_without_the_password() {
        let err = turn_from_form("", "pat", "hunter2", None, true).unwrap_err();
        assert!(err.contains("turn:turn.example.org:3478"), "{err}");
        let err = turn_from_form("turns:h:5349", "pat", "hunter2", None, true).unwrap_err();
        assert!(err.contains("TLS") && err.contains("UDP"), "{err}");
        let err =
            turn_from_form("turn:h:3478?transport=tcp", "pat", "hunter2", None, true).unwrap_err();
        assert!(err.contains("TCP"), "{err}");
        let err = turn_from_form("turn.example.org", "pat", "hunter2", None, true).unwrap_err();
        assert!(err.contains("turn:host:port"), "{err}");
        let err = turn_from_form("turn:h", " ", "hunter2", None, true).unwrap_err();
        assert!(err.contains("username"), "{err}");
        for uri in ["", "turns:h", "nope", "turn:h"] {
            if let Err(e) = turn_from_form(uri, "", "hunter2", None, true) {
                assert!(!e.contains("hunter2"), "{e}");
            }
        }
    }

    #[test]
    fn the_status_line_says_what_contacts_see() {
        assert_eq!(
            turn_status_text(None),
            "No TURN server set: connections are direct."
        );
        let only = turn_status_text(Some(("turn:h:3478", true)));
        assert!(
            only.contains("turn:h:3478") && only.contains("not yours"),
            "{only}"
        );
        let both = turn_status_text(Some(("turn:h:3478", false)));
        assert!(both.contains("direct when possible"), "{both}");
        assert!(IP_NOTICE.contains("IP address"));
    }
}
