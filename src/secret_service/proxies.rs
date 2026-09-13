use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub(super) const SERVICE_NAME: &str = "org.freedesktop.secrets";
pub(super) const SERVICE_OBJECT_PATH: &str = "/org/freedesktop/secrets";
pub(super) const COLLECTION_PATH_PREFIX: &str = "/org/freedesktop/secrets/collection/";
/// GNOME Keyring's deliberately undocumented private password interface.
pub(super) const INTERNAL_INTERFACE_NAME: &str =
    "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface";

pub(super) type Secret<'a> = (&'a ObjectPath<'a>, &'a [u8], &'a [u8], &'a str);

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
pub(super) trait SecretService {
    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets"
)]
pub(super) trait SecretCollection {
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(
    interface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
pub(super) trait GnomeInternal {
    fn unlock_with_master_password(
        &self,
        collection: &ObjectPath<'_>,
        password: Secret<'_>,
    ) -> zbus::Result<()>;

    fn change_with_master_password(
        &self,
        collection: &ObjectPath<'_>,
        original_password: Secret<'_>,
        new_password: Secret<'_>,
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use zbus::zvariant::Type;

    use super::Secret;

    #[test]
    fn secret_tuple_matches_the_secret_service_signature() {
        assert_eq!(Secret::SIGNATURE.to_string(), "(oayays)");
    }

    #[test]
    fn dh_session_input_is_a_byte_array_variant() {
        // gkd_secret_session_handle_open unwraps the outer variant itself
        // and requires the inner value to have G_VARIANT_TYPE_BYTESTRING
        // ("ay"), so the client's DH public key must travel as a byte-array
        // variant, not a string like the plain algorithm used.
        let input = zbus::zvariant::Value::from(vec![0x02u8, 0x00, 0x7f]);

        assert_eq!(input.value_signature().to_string(), "ay");
    }
}
