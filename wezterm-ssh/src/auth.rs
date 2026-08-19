use crate::session::SessionEvent;
use anyhow::Context;
use smol::channel::{bounded, Sender};

#[derive(Debug)]
pub struct AuthenticationPrompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug)]
pub struct AuthenticationEvent {
    pub username: String,
    pub instructions: String,
    pub prompts: Vec<AuthenticationPrompt>,
    pub(crate) reply: Sender<Vec<String>>,
}

impl AuthenticationEvent {
    pub async fn answer(self, answers: Vec<String>) -> anyhow::Result<()> {
        Ok(self.reply.send(answers).await?)
    }

    pub fn try_answer(self, answers: Vec<String>) -> anyhow::Result<()> {
        Ok(self.reply.try_send(answers)?)
    }
}

impl crate::sessioninner::SessionInner {
    #[cfg(feature = "ssh2")]
    fn agent_auth(&mut self, sess: &ssh2::Session, user: &str) -> anyhow::Result<bool> {
        if let Some(only) = self.config.get("identitiesonly") {
            if only == "yes" {
                log::trace!("Skipping agent auth because identitiesonly=yes");
                return Ok(false);
            }
        }

        let mut agent = sess.agent()?;
        if agent.connect().is_err() {
            // If the agent is around, we can proceed with other methods
            return Ok(false);
        }

        agent.list_identities()?;
        let identities = agent.identities()?;
        for identity in identities {
            if agent.userauth(user, &identity).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(feature = "ssh2")]
    fn pubkey_auth(
        &mut self,
        sess: &ssh2::Session,
        user: &str,
        host: &str,
    ) -> anyhow::Result<bool> {
        use std::path::{Path, PathBuf};

        if let Some(files) = self.config.get("identityfile") {
            // `split_path_list` rather than `split_whitespace` so a path
            // containing a space survives; see its doc comment.
            for file in crate::config::split_path_list(files) {
                let pubkey: PathBuf = format!("{}.pub", file).into();
                let file = Path::new(&file);

                if !file.exists() {
                    continue;
                }

                let pubkey = if pubkey.exists() {
                    Some(pubkey.as_ref())
                } else {
                    None
                };

                // We try with no passphrase first, in case the key is unencrypted
                match sess.userauth_pubkey_file(user, pubkey, &file, None) {
                    Ok(_) => {
                        log::info!("pubkey_file immediately ok for {}", file.display());
                        return Ok(true);
                    }
                    Err(_) => {
                        // Most likely cause of error is that we need a passphrase
                        // to decrypt the key, so let's prompt the user for one.
                        let (reply, answers) = bounded(1);
                        self.tx_event
                            .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                                username: "".to_string(),
                                instructions: "".to_string(),
                                prompts: vec![AuthenticationPrompt {
                                    prompt: format!(
                                        "Passphrase to decrypt {} for {}@{}:\n> ",
                                        file.display(),
                                        user,
                                        host
                                    ),
                                    echo: false,
                                }],
                                reply,
                            }))
                            .context("sending Authenticate request to user")?;

                        let answers = smol::block_on(answers.recv())
                            .context("waiting for authentication answers from user")?;

                        if answers.is_empty() {
                            anyhow::bail!("user cancelled authentication");
                        }

                        let passphrase = &answers[0];

                        match sess.userauth_pubkey_file(user, pubkey, &file, Some(passphrase)) {
                            Ok(_) => {
                                return Ok(true);
                            }
                            Err(err) => {
                                log::warn!("pubkey auth: {:#}", err);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    #[cfg(feature = "libssh-rs")]
    pub fn authenticate_libssh(&mut self, sess: &libssh_rs::Session) -> anyhow::Result<()> {
        use std::collections::HashMap;
        let tx = self.tx_event.clone();

        // Set the callback for pubkey auth
        sess.set_auth_callback(move |prompt, echo, _verify, identity| {
            let (reply, answers) = bounded(1);
            tx.try_send(SessionEvent::Authenticate(AuthenticationEvent {
                username: "".to_string(),
                instructions: "".to_string(),
                prompts: vec![AuthenticationPrompt {
                    prompt: match identity {
                        Some(ident) => format!("{} ({}): ", prompt, ident),
                        None => prompt.to_string(),
                    },
                    echo,
                }],
                reply,
            }))
            .unwrap();

            let mut answers = smol::block_on(answers.recv())
                .context("waiting for authentication answers from user")
                .unwrap();
            Ok(answers.remove(0))
        });

        use libssh_rs::{AuthMethods, AuthStatus};
        match sess.userauth_none(None)? {
            AuthStatus::Success => return Ok(()),
            _ => {}
        }

        loop {
            let auth_methods = sess.userauth_list(None)?;
            let mut status_by_method = HashMap::new();

            if auth_methods.contains(AuthMethods::PUBLIC_KEY) {
                match sess.userauth_public_key_auto(None, None)? {
                    AuthStatus::Success => return Ok(()),
                    AuthStatus::Partial => continue,
                    status => {
                        status_by_method.insert(AuthMethods::PUBLIC_KEY, status);
                    }
                }
            }

            if auth_methods.contains(AuthMethods::INTERACTIVE) {
                // How many refusals are answered here before the next method
                // is tried.
                //
                // Refusing once ended the method outright. Where the server also
                // offers `password` that costs nothing — the branch below asks
                // again — but a server offering ONLY keyboard-interactive
                // (`PasswordAuthentication no`, `KbdInteractiveAuthentication
                // yes`, which is how PAM logins are commonly configured) fell
                // straight through to "unhandled auth case", and the session
                // died on a single mistype.
                //
                // Bounded rather than left to the server, unlike the password
                // branch below: a 2FA challenge that keeps being refused must
                // still fall through to the other methods rather than hold the
                // connection here. Three matches OpenSSH's own
                // `NumberOfPasswordPrompts`.
                //
                // Refusals are counted, not prompts: one PAM conversation can
                // arrive as several `Info` rounds — a banner with no prompts,
                // then the password — and counting those would spend the budget
                // on a single attempt.
                const INTERACTIVE_ATTEMPTS: usize = 3;
                let mut denials = 0usize;
                let mut answered_this_round = false;
                loop {
                    match sess.userauth_keyboard_interactive(None, None)? {
                        AuthStatus::Success => return Ok(()),
                        AuthStatus::Info => {
                            let info = sess.userauth_keyboard_interactive_info()?;

                            let (reply, answers) = bounded(1);
                            self.tx_event
                                .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                                    username: sess.get_user_name()?,
                                    instructions: info.instruction,
                                    prompts: info
                                        .prompts
                                        .into_iter()
                                        .map(|p| AuthenticationPrompt {
                                            prompt: p.prompt,
                                            echo: p.echo,
                                        })
                                        .collect(),
                                    reply,
                                }))
                                .context("sending Authenticate request to user")?;

                            let answers = smol::block_on(answers.recv())
                                .context("waiting for authentication answers from user")?;

                            sess.userauth_keyboard_interactive_set_answers(&answers)?;

                            answered_this_round = true;
                            continue;
                        }
                        AuthStatus::Denied => {
                            // A denial the server reached without asking us
                            // anything is the method saying no, not this answer
                            // being wrong: go on to the next one.
                            if !answered_this_round {
                                break;
                            }
                            denials += 1;
                            if denials >= INTERACTIVE_ATTEMPTS {
                                break;
                            }
                            answered_this_round = false;
                            continue;
                        }
                        AuthStatus::Partial => continue,
                        status => {
                            anyhow::bail!("interactive auth status: {:?}", status);
                        }
                    }
                }
            }

            if auth_methods.contains(AuthMethods::PASSWORD) {
                // A REFUSED password is asked for again rather than ending the
                // session.
                //
                // **This same file already does that on the other backend.** The
                // ssh2 path below logs a failed `userauth_password` and lets its
                // loop re-query the methods and prompt again; the libssh path —
                // the default — bailed on the first denial instead. One mistyped
                // password therefore killed the session, and the pane was left
                // showing `password auth status: Denied` with no way back.
                // `ssh(1)` gives three tries, and so does every other client.
                //
                // The count is left to the server rather than fixed here: `sshd`
                // disconnects after `MaxAuthTries`, and that error surfaces
                // through the `?` below.
                //
                // `refused` is whether the prompt below is a RETRY. It carries
                // the reason the second time round and nothing the first: a
                // first prompt has not failed in front of anyone yet, so a line
                // above it would announce a failure that has not happened —
                // while a bare `Password: ` appearing AGAIN says nothing about
                // why.
                let mut refused = false;
                let status = loop {
                    let (reply, answers) = bounded(1);
                    self.tx_event
                        .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                            username: "".to_string(),
                            instructions: if refused {
                                "Password refused.".to_string()
                            } else {
                                String::new()
                            },
                            prompts: vec![AuthenticationPrompt {
                                prompt: "Password: ".to_string(),
                                echo: false,
                            }],
                            reply,
                        }))
                        .context("sending Authenticate request to user")?;

                    let mut answers = smol::block_on(answers.recv())
                        .context("waiting for authentication answers from user")?;
                    // An empty answer set is a cancelled prompt. `remove(0)`
                    // would panic on it, and this loop can now reach the prompt
                    // more than once.
                    if answers.is_empty() {
                        anyhow::bail!("user cancelled authentication");
                    }
                    let pw = answers.remove(0);

                    match sess.userauth_password(None, Some(&pw))? {
                        AuthStatus::Success => return Ok(()),
                        AuthStatus::Denied => {
                            refused = true;
                            continue;
                        }
                        status => break status,
                    }
                };
                match status {
                    AuthStatus::Partial => continue,
                    status => anyhow::bail!("password auth status: {:?}", status),
                }
            }

            anyhow::bail!(
                "unhandled auth case; methods={:?}, status={:?}",
                auth_methods,
                status_by_method
            );
        }
    }

    #[cfg(feature = "ssh2")]
    pub fn authenticate(
        &mut self,
        sess: &ssh2::Session,
        user: &str,
        host: &str,
    ) -> anyhow::Result<()> {
        use std::collections::HashSet;

        loop {
            if sess.authenticated() {
                return Ok(());
            }

            // Re-query the auth methods on each loop as a successful method
            // may unlock a new method on a subsequent iteration (eg: password
            // auth may then unlock 2fac)
            let methods: HashSet<&str> = sess.auth_methods(&user)?.split(',').collect();
            log::trace!("ssh auth methods: {:?}", methods);

            if !sess.authenticated() && methods.contains("publickey") {
                if self.agent_auth(sess, user)? {
                    continue;
                }

                if self.pubkey_auth(sess, user, host)? {
                    continue;
                }
            }

            if !sess.authenticated() && methods.contains("password") {
                let (reply, answers) = bounded(1);
                self.tx_event
                    .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                        username: user.to_string(),
                        instructions: "".to_string(),
                        prompts: vec![AuthenticationPrompt {
                            prompt: format!("Password for {}@{}: ", user, host),
                            echo: false,
                        }],
                        reply,
                    }))
                    .context("sending Authenticate request to user")?;

                let answers = smol::block_on(answers.recv())
                    .context("waiting for authentication answers from user")?;

                if answers.is_empty() {
                    anyhow::bail!("user cancelled authentication");
                }

                if let Err(err) = sess.userauth_password(user, &answers[0]) {
                    log::error!("while attempting password auth: {}", err);
                }
            }

            if !sess.authenticated() && methods.contains("keyboard-interactive") {
                struct Helper<'a> {
                    tx_event: &'a Sender<SessionEvent>,
                }

                impl<'a> ssh2::KeyboardInteractivePrompt for Helper<'a> {
                    fn prompt<'b>(
                        &mut self,
                        username: &str,
                        instructions: &str,
                        prompts: &[ssh2::Prompt<'b>],
                    ) -> Vec<String> {
                        let (reply, answers) = bounded(1);
                        if let Err(err) = self.tx_event.try_send(SessionEvent::Authenticate(
                            AuthenticationEvent {
                                username: username.to_string(),
                                instructions: instructions.to_string(),
                                prompts: prompts
                                    .iter()
                                    .map(|p| AuthenticationPrompt {
                                        prompt: p.text.to_string(),
                                        echo: p.echo,
                                    })
                                    .collect(),
                                reply,
                            },
                        )) {
                            log::error!("sending Authenticate request to user: {:#}", err);
                            return vec![];
                        }

                        match smol::block_on(answers.recv()) {
                            Err(err) => {
                                log::error!(
                                    "waiting for authentication answers from user: {:#}",
                                    err
                                );
                                return vec![];
                            }
                            Ok(answers) => answers,
                        }
                    }
                }

                let mut helper = Helper {
                    tx_event: &self.tx_event,
                };

                if let Err(err) = sess.userauth_keyboard_interactive(user, &mut helper) {
                    log::error!("while attempting keyboard-interactive auth: {}", err);
                }
            }
        }
    }
}
