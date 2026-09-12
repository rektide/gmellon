use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub(super) const SERVICE_NAME: &str = "org.freedesktop.secrets";
pub(super) const COLLECTION_PATH_PREFIX: &str = "/org/freedesktop/secrets/collection/";

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
    fn gnome_plain_session_input_is_a_string_variant() {
        let input = zbus::zvariant::Value::from("");

        assert_eq!(input.value_signature().to_string(), "s");
    }
}
