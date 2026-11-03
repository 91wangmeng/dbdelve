//! JumpServer as the source of a server's address and credentials.
//!
//! A profile that carries a [`JumpServer`] does not name its host, port, user
//! or password: each is issued by JumpServer's connection-token API, and
//! [`resolve`] turns the profile's `ServerConfig` into one that does, before any
//! engine sees it. The engine then connects exactly as it would to a server the
//! user had typed in, which is why nothing below `resolve` knows JumpServer
//! exists.
//!
//! The profile's own password slot holds the API key's secret, so it lives in
//! the keychain with every other password and never in `profiles.toml`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::macros::format_description;
use ureq::http::Request;

use super::{DbError, ServerConfig};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a token is reused when the profile does not say.
pub const DEFAULT_TTL_SECONDS: u32 = 60;

/// Where a profile gets its connection from, instead of typing it in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpServer {
    /// The HTTP(S) origin of JumpServer's web address, no path.
    pub url: String,
    pub asset_id: String,
    /// The personal API key's id. Its secret is the profile's password.
    pub key_id: String,
    /// The authorized account to connect as. Blank picks the only one, and
    /// refuses to guess between several.
    #[serde(default)]
    pub account: String,
    /// Seconds a token is reused before a new one is asked for, or 0 to ask
    /// every time. Only the local side of it: how long JumpServer honours a
    /// token is its own setting, and this should be the shorter of the two.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

impl Default for JumpServer {
    fn default() -> Self {
        Self {
            url: String::new(),
            asset_id: String::new(),
            key_id: String::new(),
            account: String::new(),
            ttl: DEFAULT_TTL_SECONDS,
        }
    }
}

fn default_ttl() -> u32 {
    DEFAULT_TTL_SECONDS
}

impl JumpServer {
    /// What is wrong with a field, or None. Checked on save so a mistake is
    /// read at the form rather than as a failed request.
    pub fn error(&self) -> Option<&'static str> {
        let origin = self.url.trim_end_matches('/');
        let host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"));
        if host.is_none_or(|host| host.is_empty() || host.contains(['/', '?', '#', '@'])) {
            return Some("JumpServer address must be http(s)://host[:port], with no path.");
        }
        if self.asset_id.trim().is_empty() {
            return Some("JumpServer asset id is required.");
        }
        if self.key_id.trim().is_empty() {
            return Some("JumpServer API key id is required.");
        }
        None
    }
}

#[derive(Clone)]
struct Token {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
}

struct Cached {
    token: Token,
    issued: Instant,
}

/// Keyed by everything that selects a token, so two profiles on one asset with
/// different accounts never share one. Process-wide because a profile's
/// connections (the query, its cancel, a reconnect) are separate `open`s.
static CACHE: LazyLock<Mutex<HashMap<String, Cached>>> = LazyLock::new(Mutex::default);

/// `server` with the address and credentials JumpServer issued, or a plain
/// clone when the profile has no JumpServer. `protocol` is JumpServer's name
/// for what the engine speaks.
pub fn resolve(server: &ServerConfig, protocol: &str) -> Result<ServerConfig, DbError> {
    let Some(jumpserver) = &server.jumpserver else {
        return Ok(server.clone());
    };
    let key = format!(
        "{}\n{}\n{}\n{}\n{protocol}",
        jumpserver.url, jumpserver.key_id, jumpserver.asset_id, jumpserver.account
    );
    let ttl = Duration::from_secs(u64::from(jumpserver.ttl));
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fresh = cache
        .get(&key)
        .filter(|cached| cached.issued.elapsed() < ttl)
        .map(|cached| cached.token.clone());
    let token = match fresh {
        Some(token) => token,
        None => {
            // Held across the request: two connections opening together would
            // otherwise each cost a token and an audit record.
            let token = issue(jumpserver, &server.password, protocol)?;
            cache.insert(
                key,
                Cached {
                    token: token.clone(),
                    issued: Instant::now(),
                },
            );
            token
        }
    };
    Ok(ServerConfig {
        host: token.host,
        port: Some(token.port),
        user: token.user,
        password: token.password,
        database: if server.database.is_empty() {
            token.database
        } else {
            server.database.clone()
        },
        // Resolved: a clone of this, such as the cancel connection's, reuses it
        // rather than asking again.
        jumpserver: None,
        ..server.clone()
    })
}

fn issue(jumpserver: &JumpServer, secret: &str, protocol: &str) -> Result<Token, DbError> {
    if let Some(error) = jumpserver.error() {
        return Err(failure(error));
    }
    if secret.is_empty() {
        return Err(failure(
            "The JumpServer API key secret is the connection's password, and it is blank.",
        ));
    }
    let asset = request(
        jumpserver,
        secret,
        "GET",
        &format!("/api/v1/perms/users/self/assets/{}/", jumpserver.asset_id),
        None,
        "asset authorization",
    )?;
    let account = pick_account(&names(&asset["permed_accounts"]), &jumpserver.account)?;
    if !names(&asset["permed_protocols"]).contains(&protocol.to_owned()) {
        return Err(failure(&format!(
            "This asset is not authorized for {protocol}."
        )));
    }
    let body = json!({
        "asset": jumpserver.asset_id,
        "account": account,
        "protocol": protocol,
        "connect_method": "db_guide",
    });
    let token = request(
        jumpserver,
        secret,
        "POST",
        "/api/v1/authentication/connection-token/",
        Some(body.to_string()),
        "token request",
    )?;
    let has_ticket = match &token["from_ticket"] {
        Value::Null | Value::Bool(false) => false,
        Value::String(text) => !text.is_empty(),
        _ => true,
    };
    if token["is_active"] == Value::Bool(false) || has_ticket {
        return Err(failure("This connection needs approval in JumpServer."));
    }
    let (Some(id), Some(value)) = (token["id"].as_str(), token["value"].as_str()) else {
        return Err(failure(
            "JumpServer returned an incomplete connection token.",
        ));
    };
    if id.is_empty() || value.is_empty() {
        return Err(failure(
            "JumpServer returned an incomplete connection token.",
        ));
    }
    let client = request(
        jumpserver,
        secret,
        "GET",
        &format!("/api/v1/authentication/connection-token/{id}/client-url/"),
        None,
        "gateway lookup",
    )?;
    let (host, port, database) = parse_client_url(client["url"].as_str().unwrap_or_default())?;
    Ok(Token {
        host,
        port,
        user: id.to_owned(),
        password: value.to_owned(),
        database,
    })
}

fn failure(message: &str) -> DbError {
    DbError {
        message: format!("JumpServer: {message}"),
        position: None,
    }
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["name"].as_str().map(str::to_owned))
        .collect()
}

fn pick_account(authorized: &[String], wanted: &str) -> Result<String, DbError> {
    match (wanted, authorized) {
        ("", [only]) => Ok(only.clone()),
        ("", []) => Err(failure("No account is authorized on this asset.")),
        ("", several) => Err(failure(&format!(
            "Several accounts are authorized ({}); name one.",
            several.join(", ")
        ))),
        (wanted, authorized) if authorized.iter().any(|name| name == wanted) => {
            Ok(wanted.to_owned())
        }
        (wanted, _) => Err(failure(&format!(
            "Account '{wanted}' is not authorized on this asset."
        ))),
    }
}

/// The gateway a token connects to, from the `jms://` URL the client-url
/// endpoint returns: base64 of a JSON document.
fn parse_client_url(url: &str) -> Result<(String, u16, String), DbError> {
    let bad = || failure("The gateway address it returned is not readable.");
    let payload = url.strip_prefix("jms://").ok_or_else(bad)?;
    let bytes = STANDARD.decode(payload).map_err(|_| bad())?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    let host = document["endpoint"]["host"].as_str().ok_or_else(bad)?;
    let port = document["endpoint"]["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(bad)?;
    if host.is_empty() {
        return Err(bad());
    }
    let database = document["asset"]["info"]["db_name"]
        .as_str()
        .unwrap_or_default();
    Ok((host.to_owned(), port, database.to_owned()))
}

/// What JumpServer's HTTP-signature scheme signs: the request line and two
/// headers, in this order.
fn signing_string(method: &str, path: &str, date: &str) -> String {
    format!(
        "(request-target): {} {path}\naccept: application/json\ndate: {date}",
        method.to_lowercase()
    )
}

fn http_date() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    OffsetDateTime::from_unix_timestamp(i64::try_from(seconds).unwrap_or(0))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(format_description!(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
        ))
        .unwrap_or_default()
}

fn request(
    jumpserver: &JumpServer,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    what: &str,
) -> Result<Value, DbError> {
    let date = http_date();
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = STANDARD.encode(hmac::sign(
        &key,
        signing_string(method, path, &date).as_bytes(),
    ));
    let builder = Request::builder()
        .method(method)
        .uri(format!("{}{path}", jumpserver.url.trim_end_matches('/')))
        .header("Accept", "application/json")
        .header("Date", &date)
        .header(
            "Authorization",
            format!(
                "Signature keyId=\"{}\",algorithm=\"hmac-sha256\",headers=\"(request-target) accept date\",signature=\"{signature}\"",
                jumpserver.key_id
            ),
        );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        // A redirect would carry the signed request to wherever it points.
        .max_redirects(0)
        .build()
        .into();
    let sent = match body {
        None => builder
            .body(())
            .map_err(|_| failure("The address is not a valid URL."))
            .map(|request| agent.run(request)),
        Some(body) => builder
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|_| failure("The address is not a valid URL."))
            .map(|request| agent.run(request)),
    }?;
    match sent {
        Ok(response) => response
            .into_body()
            .read_json::<Value>()
            .map_err(|_| failure(&format!("The {what} answer is not JSON."))),
        Err(ureq::Error::StatusCode(status)) => {
            Err(failure(&format!("The {what} failed: HTTP {status}.")))
        }
        Err(error) => Err(failure(&format!("The {what} failed: {error}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounts(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_signed_string_is_the_request_line_then_accept_and_date() {
        assert_eq!(
            signing_string("GET", "/api/v1/x/", "Mon, 02 Nov 2026 01:02:03 GMT"),
            "(request-target): get /api/v1/x/\naccept: application/json\ndate: Mon, 02 Nov 2026 01:02:03 GMT"
        );
    }

    #[test]
    fn the_date_is_the_rfc_1123_form_jumpserver_checks() {
        let date = http_date();
        assert!(date.ends_with(" GMT") && date.len() == 29, "{date}");
    }

    #[test]
    fn the_gateway_is_read_from_the_client_url_payload() {
        let payload = STANDARD.encode(
            r#"{"endpoint":{"host":"gw.example","port":33061},"asset":{"info":{"db_name":"app"}}}"#,
        );
        assert_eq!(
            parse_client_url(&format!("jms://{payload}")).unwrap(),
            ("gw.example".to_owned(), 33061, "app".to_owned())
        );
        assert!(parse_client_url("http://x").is_err());
        let no_port = STANDARD.encode(r#"{"endpoint":{"host":"gw.example"}}"#);
        assert!(parse_client_url(&format!("jms://{no_port}")).is_err());
    }

    #[test]
    fn an_account_is_guessed_only_when_there_is_one() {
        assert_eq!(pick_account(&accounts(&["root"]), "").unwrap(), "root");
        assert!(pick_account(&accounts(&["root", "ro"]), "").is_err());
        assert_eq!(
            pick_account(&accounts(&["root", "ro"]), "ro").unwrap(),
            "ro"
        );
        assert!(pick_account(&accounts(&["root"]), "ro").is_err());
    }

    #[test]
    fn an_address_with_a_path_or_no_scheme_is_refused() {
        let ok = JumpServer {
            url: "http://192.168.2.98".into(),
            asset_id: "a".into(),
            key_id: "k".into(),
            ..JumpServer::default()
        };
        assert_eq!(ok.error(), None);
        for url in ["192.168.2.98", "http://h/path", "http://", "https://u@h"] {
            let bad = JumpServer {
                url: url.into(),
                ..ok.clone()
            };
            assert!(bad.error().is_some(), "{url}");
        }
    }
}
