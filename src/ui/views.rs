use super::assets::{Glyph, ambient_light, chain_icon, glyph};
use super::components::*;
use super::theme::*;
use crate::*;
use iced::widget::{
    Column, Row, Space, button, column, container, row, scrollable, text, text_input,
};
use iced::{Alignment, Element, Length};

impl State {
    pub(crate) fn view(&self) -> Element<'_, Message> {
        iced::widget::stack![
            ambient_light(),
            container(
                column![
                    self.header(),
                    row![
                        container(self.sidebar()).width(Length::Fixed(260.0)),
                        container(self.main_panel())
                            .width(Length::Fill)
                            .max_width(1000),
                    ]
                    .spacing(24)
                    .height(Length::Fill),
                    self.status_bar(),
                ]
                .spacing(14),
            )
            .padding(24)
            .width(Length::Fill)
            .height(Length::Fill)
        ]
        .into()
    }

    fn header(&self) -> Element<'_, Message> {
        let (dot, label, color) = if self.connected {
            let label = match self.peers {
                0 => "Connected".to_string(),
                1 => "Connected · 1 peer".to_string(),
                n => format!("Connected · {n} peers"),
            };
            ("●", label, accent())
        } else if self.connected_url.is_some() {
            ("◌", "Connecting…".to_string(), warning())
        } else {
            ("○", "Offline".to_string(), muted())
        };
        row![
            row![
                glyph(Glyph::Wallet, 32.0),
                column![
                    text("Starlab").size(24),
                    text("Your shared wallet").size(12).color(muted())
                ]
                .spacing(2)
            ]
            .spacing(12)
            .align_y(Alignment::Center)
            .spacing(2),
            Space::new().width(Length::Fill),
            column![
                row![text(dot).color(color), text(label).size(13).color(color)]
                    .spacing(6)
                    .align_y(Alignment::Center),
                text(format!("Device {}", self.device_id))
                    .size(12)
                    .color(muted()),
            ]
            .spacing(2)
            .align_x(Alignment::End),
        ]
        .align_y(Alignment::Center)
        .into()
    }

    fn status_bar(&self) -> Element<'_, Message> {
        text(&self.status)
            .size(12)
            .color(if self.status_is_error {
                danger()
            } else {
                muted()
            })
            .into()
    }

    // ---- Sidebar ----

    fn sidebar(&self) -> Element<'_, Message> {
        let mut items = column![self.wallets_card()].spacing(16);
        items = items.push(
            column![
                tab_button("Set up wallet", Tab::Setup, self.active_tab).width(Length::Fill),
                tab_button("Sign message", Tab::Sign, self.active_tab).width(Length::Fill),
                tab_button("Activity", Tab::Activity, self.active_tab).width(Length::Fill),
                section_divider(),
                tab_button("Connection & devices", Tab::Connection, self.active_tab)
                    .width(Length::Fill),
                tab_button("Backup & restore", Tab::Backup, self.active_tab).width(Length::Fill),
            ]
            .spacing(8),
        );
        scrollable(items).into()
    }

    fn network_card(&self) -> Element<'_, Message> {
        let mut body = column![
            field(
                "Signal server",
                text_input("wss://panda.qzz.io", &self.server_url)
                    .padding(12)
                    .style(input_style)
                    .on_input(Message::ServerUrlChanged),
            ),
            field(
                "Room ID",
                text_input("Room ID", &self.room)
                    .padding(12)
                    .style(input_style)
                    .on_input(Message::RoomChanged),
            ),
            row![
                action_button("New room").on_press(Message::NewRoom),
                action_button("Copy").on_press(Message::CopyRoom),
            ]
            .spacing(8),
            hint("Devices find each other through the same server and room ID."),
        ]
        .spacing(10);

        if self.network_changed() {
            let label = if self.connected {
                "Reconnect"
            } else {
                "Connect"
            };
            body = body.push(
                action_button(label)
                    .style(primary_button)
                    .width(Length::Fill)
                    .on_press_maybe(self.can_connect().then_some(Message::Connect)),
            );
            if self.connected {
                body = body.push(hint(if self.can_connect() {
                    "Reconnect to use the new server or room."
                } else {
                    "Finish or cancel the wallet setup before switching rooms."
                }));
            }
        }

        if let Some(setup) = self.ecdsa_setup.describe() {
            body = body.push(text(setup).size(12).color(muted()));
        }
        card("Network", body.into())
    }

    fn wallets_card(&self) -> Element<'_, Message> {
        let mut body = Column::new().spacing(10);
        if self.wallets.is_empty() {
            body = body.push(hint(
                "No wallets on this device yet. Create or join one under Set up wallet.",
            ));
        } else {
            for (i, w) in self.wallets.iter().enumerate() {
                let mut entry = Column::new().spacing(3).push(
                    button(
                        row![
                            glyph(Glyph::Wallet, 20.0),
                            column![
                                text(&w.name).size(14),
                                text(format!("{} devices to sign", w.threshold)).size(11)
                            ]
                            .spacing(3)
                        ]
                        .spacing(10)
                        .align_y(Alignment::Center),
                    )
                    .width(Length::Fill)
                    .style(if i == self.active_wallet_index {
                        active_nav_button
                    } else {
                        secondary_button
                    })
                    .on_press(Message::WalletSelected(i)),
                );
                // One line per chain address of the selected account, derived
                // from the group key via the engine's account model.
                for (curve, group_key) in &w.keys {
                    let Ok(group_key) = hex::decode(group_key) else {
                        continue;
                    };
                    let Ok(addresses) = starlab_core::accounts::account_addresses(
                        curve,
                        &group_key,
                        self.selected_account,
                    ) else {
                        continue;
                    };
                    for (chain, _path, address) in addresses {
                        entry = entry.push(
                            row![
                                chain_icon(&chain, 20.0),
                                text(format!("{chain}  {}", short_addr(&address)))
                                    .size(12)
                                    .color(muted())
                            ]
                            .spacing(8)
                            .align_y(Alignment::Center),
                        );
                    }
                }
                body = body.push(entry);
            }
            // BIP-44 account picker: [Account 0] [Account 1] … [+]. Switching
            // is a pure State change — addresses below re-derive in this view.
            let choices: Vec<String> = (0..=self.max_account)
                .map(|i| format!("Account {i}"))
                .collect();
            let selected = format!("Account {}", self.selected_account);
            body = body.push(
                row![
                    glyph(Glyph::Account, 20.0),
                    text("Account").size(12).color(muted())
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            body = body.push(
                row![
                    iced::widget::pick_list(choices, Some(selected), |choice: String| {
                        Message::SelectAccount(
                            choice
                                .trim_start_matches("Account ")
                                .parse()
                                .expect("generated account choice"),
                        )
                    })
                    .padding(12)
                    .text_size(14)
                    .width(Length::Fill),
                    action_button("+").on_press(Message::AddAccount),
                ]
                .spacing(8),
            );
        }

        card("Wallets", body.into())
    }

    fn backup_tab(&self) -> Element<'_, Message> {
        let mut body = column![hint("Keep an encrypted backup of this device's wallet share. A backup never contains the complete wallet key.")].spacing(16);
        let backup = if self.wallets.is_empty() {
            self.import_blocker()
        } else {
            self.export_blocker().or(self.import_blocker())
        };
        body = body
            .push(section_divider())
            .push(text("Back up or restore").size(13))
            .push(field(
                "Key share password",
                password_input("Password", &self.passwords.backup, PasswordField::Backup),
            ))
            .push(
                row![
                    action_button("Import key share…").on_press_maybe(
                        self.import_blocker()
                            .is_none()
                            .then_some(Message::ImportShare)
                    ),
                    action_button("Export key share…").on_press_maybe(
                        self.export_blocker()
                            .is_none()
                            .then_some(Message::ExportShare)
                    ),
                ]
                .spacing(8),
            );
        body = body.push(match backup {
            Some(reason) => text(reason).size(12).color(warning()).into(),
            None => hint(
                "Export saves this device's encrypted key share of the selected wallet; \
                 import restores one.",
            ),
        });

        card("Backup & restore", body.into())
    }

    // ---- Main area ----

    fn main_panel(&self) -> Element<'_, Message> {
        let mut content = Column::new().spacing(14);
        if let Some(banner) = self.setup_banner() {
            content = content.push(banner);
        }
        if let Some(requests) = self.signature_requests() {
            content = content.push(requests);
        }
        content = content.push(match self.active_tab {
            Tab::Setup if self.ceremony_open || self.dkg_active => self.ceremony_details(),
            Tab::Setup => self.setup_tab(),
            Tab::Sign => self.sign_tab(),
            Tab::Activity => self.activity_tab(),
            Tab::Connection => self.network_card(),
            Tab::Backup => self.backup_tab(),
        });
        scrollable(content).into()
    }

    fn ceremony_details(&self) -> Element<'_, Message> {
        let mut body =
            column![hint("Keep every device online until your wallet is ready.")].spacing(16);
        if let Some(session) = &self.active_session {
            body = body.push(
                text(format!(
                    "{} of {} devices will approve each signature",
                    session.threshold, session.total
                ))
                .size(16),
            );
            body = body.push(
                text(format!(
                    "{} of {} devices joined",
                    session.participants.len(),
                    session.total
                ))
                .size(13)
                .color(muted()),
            );
            for device in &session.participants {
                let label = if device == &self.device_id {
                    format!("{device} (this device)")
                } else {
                    device.clone()
                };
                body = body.push(
                    row![
                        glyph(Glyph::Connection, 20.0),
                        text(label).size(14),
                        Space::new().width(Length::Fill),
                        text("Joined").size(12).color(accent())
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                );
            }
        } else {
            body = body.push(hint("Waiting for the current setup's device information."));
        }
        card("Current wallet setup", body.into())
    }

    /// Pinned while a wallet setup is running: who joined, the invite to
    /// share, DKG progress, and the way out.
    fn setup_banner(&self) -> Option<Element<'_, Message>> {
        if !(self.ceremony_open || self.dkg_active) {
            return None;
        }
        if self.ecdsa_keygen {
            return Some(self.ecdsa_keygen_banner());
        }
        let own = self.own_invite();
        let joined = self.active_session.as_ref().map(|s| {
            format!(
                "{} of {} devices have joined.",
                s.participants.len(),
                s.total
            )
        });
        let (title, detail) = if self.dkg_active {
            (
                "Generating keys",
                format!(
                    "Round {} of 2 — keep every device online until it finishes.",
                    self.dkg_round.max(1)
                ),
            )
        } else if own.is_some() {
            (
                "Waiting for devices to join",
                format!(
                    "{} Share the invite ID with the other devices.",
                    joined.unwrap_or_default()
                ),
            )
        } else {
            (
                "Joined — waiting for the other devices",
                joined.unwrap_or_default(),
            )
        };

        let mut body = column![
            row![
                text(title).size(15),
                Space::new().width(Length::Fill),
                action_button("Cancel")
                    .style(button::danger)
                    .on_press(Message::CancelSetup),
            ]
            .align_y(Alignment::Center),
            text(detail).size(13).color(muted()),
        ]
        .spacing(8);
        if let Some(invite) = own.filter(|_| !self.dkg_active) {
            body = body.push(
                row![
                    text("Invite ID").size(12).color(muted()),
                    text(&invite.id).size(13),
                    Space::new().width(Length::Fill),
                    action_button("Copy invite").on_press(Message::CopyInvite),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
        }
        body = body.push(ceremony_steps(if self.dkg_active { 1 } else { 0 }));
        Some(
            container(body)
                .padding(20)
                .width(Length::Fill)
                .style(highlight_style)
                .into(),
        )
    }

    /// The wallet's FROST keys are done; its Ethereum key (threshold ECDSA)
    /// is being made — waiting for this device's safe primes first if they
    /// aren't ready yet.
    fn ecdsa_keygen_banner(&self) -> Element<'_, Message> {
        let detail = ecdsa_keygen_detail(self.ecdsa_phase, self.ecdsa_setup);
        container(
            column![
                row![
                    row![
                        chain_icon("ethereum", 24.0),
                        text("Creating Ethereum wallet").size(16)
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                    Space::new().width(Length::Fill),
                    action_button("Cancel")
                        .style(button::danger)
                        .on_press(Message::CancelSetup),
                ]
                .align_y(Alignment::Center),
                text(detail).size(13).color(muted()),
                ceremony_steps(if self.ecdsa_phase == Some(DkgPhase::Keygen) {
                    2
                } else {
                    1
                }),
            ]
            .spacing(8),
        )
        .padding(20)
        .width(Length::Fill)
        .style(highlight_style)
        .into()
    }

    /// Pinned while a peer asks this device to co-sign.
    fn signature_requests(&self) -> Option<Element<'_, Message>> {
        let request = self
            .signing_request
            .as_ref()
            .filter(|r| r.session_id.is_some())?;
        let blocker = self.approve_blocker();
        let actions: Element<'_, Message> = match &self.signing_state {
            SigningState::Commitment | SigningState::Share | SigningState::Aggregating => {
                text("Co-signing…").size(13).color(accent()).into()
            }
            SigningState::Failed(error) => row![
                text(format!("Signing failed: {error}"))
                    .size(12)
                    .color(danger()),
                Space::new().width(Length::Fill),
                action_button("Dismiss").on_press(Message::DismissSigning),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
            _ => row![
                text(blocker.unwrap_or_default()).size(12).color(warning()),
                Space::new().width(Length::Fill),
                action_button("Reject")
                    .style(secondary_button)
                    .on_press(Message::RejectSignatureRequest(request.id.clone())),
                action_button("Approve & sign")
                    .style(primary_button)
                    .on_press_maybe(
                        blocker
                            .is_none()
                            .then(|| Message::ApproveSignatureRequest(request.id.clone())),
                    ),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        };
        let mut body = column![
            row![
                chain_icon(&request.chain, 24.0),
                text("Signature request").size(18)
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            text("Another device of this wallet asks this device to co-sign.").size(13),
            text(self.describe_account_wallet(&request.wallet_id))
                .size(12)
                .color(muted()),
        ]
        .spacing(4);
        if let Some(label) = &request.display_label {
            body = body.push(text(label).size(12).color(faint()));
        }
        body = body
            .push(field(
                if matches!(request.chain.as_str(), "ethereum" | "bitcoin") {
                    "Signing digest (hex)"
                } else {
                    "Message bytes (hex)"
                },
                text(&request.message_hex)
                    .size(12)
                    .color(faint())
                    .wrapping(iced::widget::text::Wrapping::Glyph),
            ))
            .push(hint("Review the message on the requesting device."));
        let awaiting = !matches!(
            self.signing_state,
            SigningState::Commitment
                | SigningState::Share
                | SigningState::Aggregating
                | SigningState::Failed(_)
        );
        if awaiting {
            body = body.push(
                container(field(
                    "Wallet password",
                    password_input(
                        "Unlocks this device's key share",
                        &self.passwords.unlock,
                        PasswordField::Unlock,
                    ),
                ))
                .width(Length::Fixed(360.0)),
            );
        }
        body = body.push(actions);
        Some(
            container(body)
                .padding(20)
                .width(Length::Fill)
                .style(highlight_style)
                .into(),
        )
    }

    /// Create and Join side by side: each section has exactly one action.
    fn setup_tab(&self) -> Element<'_, Message> {
        let create_blocker = self.create_blocker();
        let create = card(
            "Create a new wallet",
            column![
                text(format!(
                    "Start a {DEFAULT_THRESHOLD}-of-{DEFAULT_TOTAL} wallet on this device, then share \
                     its invite ID with {} other devices. Any {DEFAULT_THRESHOLD} of the \
                     {DEFAULT_TOTAL} can sign.",
                    DEFAULT_TOTAL - 1
                ))
                .size(13)
                .color(muted()),
                field(
                    "Wallet name",
                    text_input("e.g. Treasury", &self.wallet_name)
                        .padding(12).style(input_style).on_input(Message::WalletNameChanged),
                ),
                new_password_fields(
                    &self.passwords.create,
                    &self.passwords.create_confirm,
                    PasswordField::Create,
                    PasswordField::CreateConfirm,
                ),
                action_row(
                    action_button("Create wallet")
                        .style(primary_button)
                        .on_press_maybe(create_blocker.is_none().then_some(Message::CreateWallet)),
                    create_blocker,
                ),
            ]
            .spacing(12)
            .into(),
        );

        let mut invites = Column::new().spacing(6);
        let wallet_invites = wallet_invites(&self.device_id, &self.invites);
        if wallet_invites.is_empty() {
            invites = invites.push(hint("No invites in this room yet."));
        }
        for invite in wallet_invites {
            invites = invites.push(
                button(
                    column![
                        row![
                            glyph(Glyph::Connection, 20.0),
                            text(format!("Invitation from {}", invite.proposer)).size(14)
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                        text(format!(
                            "from {} · {} of {} joined",
                            invite.proposer,
                            invite.participants.len(),
                            invite.total
                        ))
                        .size(11),
                    ]
                    .spacing(2),
                )
                .width(Length::Fill)
                .style(if invite.id == self.invite_id.trim() {
                    primary_button
                } else {
                    secondary_button
                })
                .on_press(Message::InviteIdChanged(invite.id.clone())),
            );
        }
        let join_blocker = self.join_blocker();
        let join = card(
            "Join a wallet",
            column![
                text("Another device started it: pick its invite, or paste the invite ID.")
                    .size(13)
                    .color(muted()),
                field("Invites in this room", invites),
                field(
                    "Invite ID",
                    text_input("Paste invite ID", &self.invite_id)
                        .padding(12)
                        .style(input_style)
                        .on_input(Message::InviteIdChanged),
                ),
                new_password_fields(
                    &self.passwords.join,
                    &self.passwords.join_confirm,
                    PasswordField::Join,
                    PasswordField::JoinConfirm,
                ),
                action_row(
                    action_button("Join wallet")
                        .style(primary_button)
                        .on_press_maybe(join_blocker.is_none().then_some(Message::JoinWallet)),
                    join_blocker,
                ),
            ]
            .spacing(12)
            .into(),
        );

        row![create, join].spacing(14).into()
    }

    fn sign_tab(&self) -> Element<'_, Message> {
        let Some(wallet) = self.active_wallet() else {
            return card(
                "Sign a message",
                column![
                    hint("You need a shared wallet before you can sign."),
                    action_button("Set up a wallet").on_press(Message::TabSelected(Tab::Setup)),
                ]
                .spacing(12)
                .into(),
            );
        };

        let mut chains = Row::new().spacing(8);
        for (key, label) in device_chains(self.signing_curve) {
            if wallet_has_chain(wallet, key) {
                chains = chains.push(
                    button(
                        row![chain_icon(key, 24.0), text(label).size(14)]
                            .spacing(8)
                            .align_y(Alignment::Center),
                    )
                    .padding([10, 14])
                    .style(if key == self.sign_chain {
                        primary_button
                    } else {
                        secondary_button
                    })
                    .on_press(Message::SignChainSelected(key)),
                );
            }
        }
        let address: Element<'_, Message> = match self.signing_address() {
            Some((address, _path)) => {
                row![chain_icon(self.sign_chain, 24.0), text(address).size(13)]
                    .spacing(10)
                    .align_y(Alignment::Center)
                    .into()
            }
            None => hint("This wallet has no key for this chain on this device."),
        };
        let message_hint = match self.sign_chain {
            "ethereum" => {
                "Hex bytes; signed as an EIP-191 personal message with the wallet's \
                 threshold-ECDSA key."
            }
            "bitcoin" => "The 32-byte BIP-341 sighash, in hex.",
            _ => "Hex bytes to sign.",
        };

        let signing = self.pending_action == Some(PendingAction::Sign);
        let blocker = if signing { None } else { self.sign_blocker() };
        let mut body = column![
            column![
                text(format!(
                    "{} · Account {}",
                    wallet.name, self.selected_account
                ))
                .size(15),
                hint("Choose the wallet and account in the left panel."),
            ]
            .spacing(4),
            field("Chain", chains),
            field("Signing address", address),
            field(
                "Message (hex bytes)",
                text_input("0x…", &self.sign_hex)
                    .padding(12)
                    .style(input_style)
                    .on_input(Message::SignHexChanged),
            ),
            hint("Enter the message as hexadecimal bytes."),
            field(
                "Wallet password",
                password_input(
                    "Unlocks this device's key share",
                    &self.passwords.unlock,
                    PasswordField::Unlock,
                ),
            ),
            action_row(
                action_button(if signing {
                    "Signing…"
                } else {
                    "Request signature"
                })
                .style(primary_button)
                .on_press_maybe((blocker.is_none() && !signing).then_some(Message::Sign),),
                blocker,
            ),
        ]
        .spacing(12);

        body = body.push(
            action_button(if self.show_signing_details {
                "Hide signing details"
            } else {
                "Show signing details"
            })
            .on_press(Message::ToggleSigningDetails),
        );
        if self.show_signing_details {
            body = body.push(hint(message_hint));
            if let Some((_, path)) = self.signing_address() {
                body = body.push(text(path).size(12).color(muted()));
            }
        }
        if signing {
            body = body.push(
                text(signing_phase(&self.signing_state))
                    .size(13)
                    .color(accent()),
            );
        } else if let SigningState::Failed(error) = &self.signing_state {
            body = body.push(
                text(format!("Signing failed: {error}"))
                    .size(13)
                    .color(danger()),
            );
        }
        if !self.last_signature.is_empty() {
            let summary = signature_summary(self.last_signed.as_ref(), &self.last_signature);
            let mut details = Column::new().spacing(4);
            if self.last_signed.as_ref().is_some_and(|s| s.cosigned) {
                details = details.push(hint(
                    "Co-signed for another device's request — it has this signature too.",
                ));
            }
            details = details.push(
                row![
                    text(&self.last_signature)
                        .size(12)
                        .width(Length::Fill)
                        .wrapping(iced::widget::text::Wrapping::Glyph),
                    action_button("Copy").on_press(Message::CopySignature),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
            if self.show_signing_details {
                for line in summary.parts {
                    details = details.push(text(line).size(12).color(muted()));
                }
            }
            details = details.push(
                row![
                    glyph(Glyph::Check, 20.0),
                    text(summary.verification)
                        .size(12)
                        .color(if summary.verified { accent() } else { danger() })
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            body = body.push(field(
                if self.show_signing_details {
                    summary.label
                } else {
                    "Signature"
                },
                details,
            ));
        }

        card("Sign a message", body.into())
    }

    fn activity_tab(&self) -> Element<'_, Message> {
        let mut lines = Column::new().spacing(12);
        if self.log_messages.is_empty() {
            lines = lines.push(
                column![
                    glyph(Glyph::Activity, 36.0),
                    text("No activity yet").size(18),
                    hint("Wallet setup, signatures and backups will appear here.")
                ]
                .spacing(12)
                .padding(20),
            );
        }
        for line in self.log_messages.iter().rev() {
            let (timestamp, message) = line
                .split_once(' ')
                .filter(|(prefix, _)| prefix.len() == 8 && prefix.contains(':'))
                .unwrap_or(("", line.as_str()));
            let failed = message.starts_with("[ERROR]");
            let message = message
                .strip_prefix("[INFO] ")
                .or_else(|| message.strip_prefix("[ERROR] "))
                .unwrap_or(message);
            let title: String = message.chars().take(100).collect();
            let mut entry = column![
                row![
                    glyph(Glyph::Activity, 20.0),
                    text(title).size(14).width(Length::Fill),
                    text(timestamp).size(11).color(muted())
                ]
                .spacing(10)
                .align_y(Alignment::Center),
                text(if failed {
                    "Needs attention"
                } else {
                    "Wallet event"
                })
                .size(11)
                .color(if failed { danger() } else { muted() })
            ]
            .spacing(6);
            if self.show_activity_details {
                entry = entry.push(
                    text(line)
                        .size(12)
                        .color(muted())
                        .wrapping(iced::widget::text::Wrapping::Glyph),
                );
            }
            lines = lines.push(
                container(entry)
                    .padding(16)
                    .width(Length::Fill)
                    .style(panel_style),
            );
        }
        card(
            "Activity",
            column![
                action_button(if self.show_activity_details {
                    "Hide technical details"
                } else {
                    "Show technical details"
                })
                .on_press(Message::ToggleActivityDetails),
                lines
            ]
            .spacing(16)
            .into(),
        )
    }
}
