//! Local presence for raw content proofs (plan §5.11.9, D12/D14). On a
//! signed macOS build the desktop runs LocalAuthentication before it sends
//! Core a `local_presence` proof, so a script driving the WebView cannot
//! approve raw access alone. It binds no key: Core accepts the proof because
//! only this desktop holds the operator token and the keychain local key.

/// What one LocalAuthentication attempt ended in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Verified,
    /// The user or the system dismissed the prompt.
    Cancelled,
    /// This build or machine cannot check presence: not macOS, a debug or
    /// unsigned build, or no Touch ID and no login password policy.
    Unsupported,
}

pub trait PresenceVerifier: Send + Sync {
    /// Whether `verify` can succeed on this machine right now.
    fn available(&self) -> bool;
    /// Shows the system prompt and blocks until it is answered.
    fn verify(&self, reason: &str) -> Presence;
}

/// The verifier for this build.
pub fn system() -> &'static dyn PresenceVerifier {
    &SystemPresence
}

struct SystemPresence;

impl PresenceVerifier for SystemPresence {
    fn available(&self) -> bool {
        enabled() && platform::available()
    }

    fn verify(&self, reason: &str) -> Presence {
        if !enabled() {
            return Presence::Unsupported;
        }
        platform::verify(reason)
    }
}

/// Only builds that keep the local key in the keychain get a `local`
/// envelope, so only they can use presence as proof.
fn enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        // The code signature check does not change while the app runs.
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(crate::kek_store::keychain_enabled)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};

    use super::Presence;

    /// Touch ID, a paired Apple Watch, or the login password.
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;
    /// An unanswered prompt is withdrawn so the approval dialog recovers.
    const WAIT: Duration = Duration::from_secs(180);

    pub fn available() -> bool {
        // SAFETY: a fresh context is only queried on this thread.
        unsafe { LAContext::new().canEvaluatePolicy_error(POLICY) }.is_ok()
    }

    pub fn verify(reason: &str) -> Presence {
        // SAFETY: the context outlives the evaluation: it is kept until the
        // reply arrives or it is invalidated below.
        let context = unsafe { LAContext::new() };
        if unsafe { context.canEvaluatePolicy_error(POLICY) }.is_err() {
            return Presence::Unsupported;
        }
        let (sender, receiver) = mpsc::sync_channel::<Result<(), isize>>(1);
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let outcome = if success.as_bool() {
                Ok(())
            } else {
                // SAFETY: LocalAuthentication passes nil or a valid error.
                Err(unsafe { error.as_ref() }.map_or(0, NSError::code))
            };
            let _ = sender.try_send(outcome);
        });
        let reason = NSString::from_str(reason);
        // SAFETY: the reply only moves a Send channel end, and the prompt
        // reason is a non-empty string.
        unsafe { context.evaluatePolicy_localizedReason_reply(POLICY, &reason, &reply) };
        match receiver.recv_timeout(WAIT) {
            Ok(Ok(())) => Presence::Verified,
            Ok(Err(code)) => classify(code),
            Err(_) => {
                // SAFETY: invalidating ends the pending prompt.
                unsafe { context.invalidate() };
                Presence::Cancelled
            }
        }
    }

    fn classify(code: isize) -> Presence {
        let unsupported = [
            LAError::PasscodeNotSet,
            LAError::BiometryNotAvailable,
            LAError::BiometryNotEnrolled,
            LAError::NotInteractive,
            LAError::InvalidContext,
        ];
        if unsupported.iter().any(|error| error.0 == code) {
            Presence::Unsupported
        } else {
            Presence::Cancelled
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn failures_split_into_cancelled_and_unsupported() {
            assert_eq!(classify(LAError::UserCancel.0), Presence::Cancelled);
            assert_eq!(classify(LAError::SystemCancel.0), Presence::Cancelled);
            assert_eq!(
                classify(LAError::AuthenticationFailed.0),
                Presence::Cancelled
            );
            assert_eq!(classify(LAError::PasscodeNotSet.0), Presence::Unsupported);
            assert_eq!(classify(LAError::NotInteractive.0), Presence::Unsupported);
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::Presence;

    pub fn available() -> bool {
        false
    }

    pub fn verify(_reason: &str) -> Presence {
        Presence::Unsupported
    }
}

#[cfg(test)]
pub mod testing {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{Presence, PresenceVerifier};

    /// Answers every prompt with one fixed result and counts the prompts.
    pub struct FakePresence {
        pub result: Presence,
        pub prompts: AtomicUsize,
    }

    impl FakePresence {
        pub fn new(result: Presence) -> Self {
            Self {
                result,
                prompts: AtomicUsize::new(0),
            }
        }

        pub fn prompts(&self) -> usize {
            self.prompts.load(Ordering::SeqCst)
        }
    }

    impl PresenceVerifier for FakePresence {
        fn available(&self) -> bool {
            self.result != Presence::Unsupported
        }

        fn verify(&self, _reason: &str) -> Presence {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            self.result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_non_macos_builds_never_offer_presence() {
        // Tests are debug builds, which keep the key file.
        assert!(!system().available());
        assert_eq!(system().verify("unlock"), Presence::Unsupported);
    }
}
