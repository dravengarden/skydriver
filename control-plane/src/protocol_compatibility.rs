use serde::Serialize;
use worker::{Request, Response, ResponseBuilder, Result};

pub(crate) const PROTOCOL_EPOCH: u64 = 2;
pub(crate) const MINIMUM_SDK_VERSION: &str = "0.3.0";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const COMPATIBILITY_SCHEMA: &str = "carrack.protocol-compatibility.v1";
const ERROR_SCHEMA: &str = "carrack.protocol-error.v1";
const PROTOCOL_EPOCH_HEADER: &str = "Carrack-Protocol-Epoch";
const SDK_VERSION_HEADER: &str = "Carrack-SDK-Version";

#[derive(Serialize)]
struct CompatibilityResponse {
    schema: &'static str,
    protocol_epoch: u64,
    minimum_sdk_version: &'static str,
    server_version: &'static str,
    enforcement: &'static str,
    upgrade_command: &'static str,
}

#[derive(Serialize)]
struct UpgradeRequiredResponse {
    schema: &'static str,
    code: &'static str,
    message: &'static str,
    protocol_epoch: u64,
    minimum_sdk_version: &'static str,
    server_version: &'static str,
    upgrade_command: &'static str,
}

/// Returns the unauthenticated compatibility contract used before any V2 I/O.
pub(crate) fn describe() -> Result<Response> {
    Response::from_json(&CompatibilityResponse {
        schema: COMPATIBILITY_SCHEMA,
        protocol_epoch: PROTOCOL_EPOCH,
        minimum_sdk_version: MINIMUM_SDK_VERSION,
        server_version: SERVER_VERSION,
        enforcement: "required",
        upgrade_command: "upgrade Carrack with the package manager that installed it",
    })
}

/// Rejects V2 calls before authentication, metadata mutation, or provider I/O.
pub(crate) fn enforce(request: &Request) -> Result<Option<Response>> {
    let epoch = request.headers().get(PROTOCOL_EPOCH_HEADER)?;
    let compatible = epoch.as_deref() == Some("2") && sdk_version_at_least(request, (0, 3, 0))?;

    if compatible {
        return Ok(None);
    }

    let response = ResponseBuilder::new()
        .with_status(426)
        .with_header("Cache-Control", "no-store")?
        .from_json(&UpgradeRequiredResponse {
            schema: ERROR_SCHEMA,
            code: "sdk_upgrade_required",
            message: "Carrack protocol or SDK version is incompatible",
            protocol_epoch: PROTOCOL_EPOCH,
            minimum_sdk_version: MINIMUM_SDK_VERSION,
            server_version: SERVER_VERSION,
            upgrade_command: "upgrade Carrack with the package manager that installed it",
        })?;
    Ok(Some(response))
}

/// Checks one additive feature floor after the epoch-wide compatibility gate.
pub(crate) fn sdk_version_at_least(request: &Request, minimum: (u64, u64, u64)) -> Result<bool> {
    Ok(request
        .headers()
        .get(SDK_VERSION_HEADER)?
        .as_deref()
        .and_then(parse_version)
        .is_some_and(|candidate| candidate >= minimum))
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let mut fields = core.split('.');
    let version = (
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    );
    (fields.next().is_none() && !value.contains('+')).then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_three_part_versions() {
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("1.2.3-dev"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.1"), None);
        assert_eq!(parse_version("0.1.0.1"), None);
        assert_eq!(parse_version("0.1.0+local"), None);
    }
}
