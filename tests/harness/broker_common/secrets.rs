//! Disposable generated proof secrets held under the zeroize-on-drop
//! discipline.

use zeroize::Zeroizing;

use crate::common;

/// Generated, zeroized-on-drop proof secrets and the non-secret run tag used
/// to make the second fixture label distinguishable per run. The `login`
/// collection deliberately carries no run tag: its stable ID must be exactly
/// `login`.
pub struct ProofSecrets {
    pub run_tag: String,
    pub login: Zeroizing<Vec<u8>>,
    pub second: Zeroizing<Vec<u8>>,
    pub wrong: Zeroizing<Vec<u8>>,
    pub login_two: Zeroizing<Vec<u8>>,
    /// The rotated password for the second collection: `second` becomes
    /// invalid and `second_two` unlocks after a proven `gmellon change`.
    pub second_two: Zeroizing<Vec<u8>>,
    /// The passphrase of the proof's generated SSH key; it must appear in
    /// no stream, artifact, or bus body in the clear.
    pub key_pass: Zeroizing<Vec<u8>>,
    /// The rotation passphrase: the proof's SSH key is regenerated at the
    /// same path under it, making the stored `key_pass` item stale for the
    /// `ssh-verify` proof. Held under the same redaction discipline as
    /// every other generated secret.
    pub key_pass_two: Zeroizing<Vec<u8>>,
}

impl ProofSecrets {
    pub fn generate() -> Self {
        let login = common::random_password();
        let second = common::distinct_password(&[&login]);
        let login_two = common::distinct_password(&[&login, &second]);
        let second_two = common::distinct_password(&[&login, &second, &login_two]);
        let wrong = common::distinct_password(&[&login, &second, &login_two, &second_two]);
        let key_pass =
            common::distinct_password(&[&login, &second, &login_two, &second_two, &wrong]);
        let key_pass_two = common::distinct_password(&[
            &login,
            &second,
            &login_two,
            &second_two,
            &wrong,
            &key_pass,
        ]);

        // Not a secret: a printable tag identifying this run's second fixture.
        let mut random = [0_u8; 4];
        common::read_urandom(&mut random);
        let run_tag = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        Self {
            run_tag,
            login,
            second,
            wrong,
            login_two,
            second_two,
            key_pass,
            key_pass_two,
        }
    }

    pub fn all_slices(&self) -> Vec<&[u8]> {
        vec![
            self.login.as_slice(),
            self.second.as_slice(),
            self.wrong.as_slice(),
            self.login_two.as_slice(),
            self.second_two.as_slice(),
            self.key_pass.as_slice(),
            self.key_pass_two.as_slice(),
        ]
    }

    pub fn named(&self) -> [(&'static str, &[u8]); 7] {
        [
            ("login", self.login.as_slice()),
            ("second", self.second.as_slice()),
            ("wrong", self.wrong.as_slice()),
            ("login_two", self.login_two.as_slice()),
            ("second_two", self.second_two.as_slice()),
            ("key_pass", self.key_pass.as_slice()),
            ("key_pass_two", self.key_pass_two.as_slice()),
        ]
    }
}
