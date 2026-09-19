//! The deterministic stdout renderers: one tab-separated table per
//! listing command, the `status` summary block, and the probe wording.
//! Every table header and column order here is output contract, pinned by
//! unit tests and the broker proofs.

use gmellon::secret_service::{Collection, CollectionId, InterfaceProbe, Item};

pub(crate) fn render_collections(collections: &[Collection]) -> String {
    let mut output = String::from("ID\tLOCKED\tLABEL\n");
    for collection in collections {
        let locked = if collection.locked { "yes" } else { "no" };
        output.push_str(collection.id.as_str());
        output.push('\t');
        output.push_str(locked);
        output.push('\t');
        output.extend(collection.label.escape_debug());
        output.push('\n');
    }
    output
}

/// The `status` collection block: a totals line, then one indented
/// ID-and-lock-state line per collection (already sorted by the client).
pub(crate) fn render_lock_summary(collections: &[Collection]) -> String {
    let locked = collections
        .iter()
        .filter(|collection| collection.locked)
        .count();
    let mut output = format!(
        "collections: {} total, {} locked\n",
        collections.len(),
        locked
    );
    let width = collections
        .iter()
        .map(|collection| collection.id.as_str().len())
        .max()
        .unwrap_or(0);
    for collection in collections {
        let state = if collection.locked {
            "locked"
        } else {
            "unlocked"
        };
        output.push_str(&format!(
            "  {:<width$}  {}\n",
            collection.id.as_str(),
            state,
            width = width
        ));
    }
    output
}

pub(crate) fn render_items(items: &[Item]) -> String {
    let mut output = String::from("LABEL\tLOCKED\tATTRIBUTES\n");
    for item in items {
        let locked = if item.locked { "yes" } else { "no" };
        output.extend(item.label.escape_debug());
        output.push('\t');
        output.push_str(locked);
        output.push('\t');
        let mut first = true;
        for (key, value) in &item.attributes {
            if !first {
                output.push(',');
            }
            first = false;
            output.push_str(key);
            output.push('=');
            output.extend(value.escape_debug());
        }
        output.push('\n');
    }
    output
}

pub(crate) fn render_ssh_items(entries: &[(CollectionId, Item)]) -> String {
    let mut output = String::from("KEY\tCOLLECTION\tLOCKED\tASKPASS\n");
    for (collection, item) in entries {
        let locked = if item.locked { "yes" } else { "no" };
        let askpass = if item.askpass_allowed() { "yes" } else { "no" };
        output.extend(item.ssh_key_path().unwrap_or_default().escape_debug());
        output.push('\t');
        output.push_str(collection.as_str());
        output.push('\t');
        output.push_str(locked);
        output.push('\t');
        output.push_str(askpass);
        output.push('\n');
    }
    output
}

pub(crate) fn private_interface_wording(probe: InterfaceProbe) -> &'static str {
    match probe {
        InterfaceProbe::Available => "available",
        InterfaceProbe::Unavailable => "unavailable",
        InterfaceProbe::Unknown => "unknown (introspection failed)",
    }
}

#[cfg(test)]
mod tests {
    use zbus::zvariant::OwnedObjectPath;

    use super::*;

    #[test]
    fn status_rendering_summarizes_lock_state_and_aligns_ids() {
        let collections = [
            Collection {
                id: CollectionId::new("login").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                    .unwrap(),
                label: "Login".to_owned(),
                locked: true,
            },
            Collection {
                id: CollectionId::new("work").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work")
                    .unwrap(),
                label: "Work".to_owned(),
                locked: false,
            },
        ];

        assert_eq!(
            render_lock_summary(&collections),
            "collections: 2 total, 1 locked\n  login  locked\n  work   unlocked\n"
        );
    }

    #[test]
    fn status_rendering_handles_the_empty_service() {
        assert_eq!(render_lock_summary(&[]), "collections: 0 total, 0 locked\n");
    }

    #[test]
    fn private_interface_probe_wording_is_stable() {
        assert_eq!(
            private_interface_wording(InterfaceProbe::Available),
            "available"
        );
        assert_eq!(
            private_interface_wording(InterfaceProbe::Unavailable),
            "unavailable"
        );
        assert_eq!(
            private_interface_wording(InterfaceProbe::Unknown),
            "unknown (introspection failed)"
        );
    }

    #[test]
    fn ssh_rendering_reports_the_askpass_grant_column() {
        let entries = [(
            CollectionId::new("login").unwrap(),
            Item {
                label: "Unlock password for: deck".to_owned(),
                locked: false,
                attributes: [
                    ("gmellon:askpass", "allow"),
                    ("unique", "ssh-store:/home/me/.ssh/deck"),
                    ("xdg:schema", "org.freedesktop.Secret.Generic"),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login/x")
                    .unwrap(),
            },
        )];

        assert_eq!(
            render_ssh_items(&entries),
            "KEY\tCOLLECTION\tLOCKED\tASKPASS\n/home/me/.ssh/deck\tlogin\tno\tyes\n"
        );
    }

    #[test]
    fn collection_rendering_is_deterministic_and_escapes_controls() {
        let collections = [
            Collection {
                id: CollectionId::new("login").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                    .unwrap(),
                label: "Login".to_owned(),
                locked: true,
            },
            Collection {
                id: CollectionId::new("work").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work")
                    .unwrap(),
                label: "Work\nSecrets".to_owned(),
                locked: false,
            },
        ];

        assert_eq!(
            render_collections(&collections),
            "ID\tLOCKED\tLABEL\nlogin\tyes\tLogin\nwork\tno\tWork\\nSecrets\n"
        );
    }
}
