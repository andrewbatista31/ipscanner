use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBanner {
    pub url: String,
    pub title: Option<String>,
    pub server: Option<String>,
    pub status: u16,
}

/// Fetch an HTTP banner (HTML <title> + Server header) from the given host on
/// whichever of HTTPS:443 / HTTP:80 / HTTPS:8443 / HTTP:8080 is open. Self-
/// signed certificates are accepted because most internal device management
/// UIs ship with them.
pub async fn fetch(addr: Ipv4Addr, open_ports: &[u16], timeout: Duration) -> Option<HttpBanner> {
    let url = pick_url(addr, open_ports)?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .user_agent("ipscanner/0.3 (+https://github.com/andrewbatista31/ipscanner)")
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()
        .ok()?;

    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let server = resp
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Read at most ~64 KB of the body — titles always appear in the <head>.
    let bytes = resp.bytes().await.ok()?;
    let snippet_end = bytes.len().min(65_536);
    let snippet = String::from_utf8_lossy(&bytes[..snippet_end]);
    let title = extract_title(&snippet);

    Some(HttpBanner {
        url,
        title,
        server,
        status,
    })
}

fn pick_url(addr: Ipv4Addr, open_ports: &[u16]) -> Option<String> {
    if open_ports.contains(&443) {
        Some(format!("https://{addr}/"))
    } else if open_ports.contains(&80) {
        Some(format!("http://{addr}/"))
    } else if open_ports.contains(&8443) {
        Some(format!("https://{addr}:8443/"))
    } else if open_ports.contains(&8080) {
        Some(format!("http://{addr}:8080/"))
    } else {
        None
    }
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = lower[start..].find('>')? + start + 1;
    let end = lower[after..].find("</title>")? + after;
    let raw = html.get(after..end)?.trim();
    if raw.is_empty() {
        None
    } else {
        // Decode a couple of the most common entities; not a full HTML parser.
        let cleaned = raw
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ");
        // Collapse runs of whitespace.
        let cleaned: String = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_title() {
        assert_eq!(extract_title("<title>Hello</title>"), Some("Hello".into()));
    }

    #[test]
    fn extracts_with_attrs_and_entities() {
        let html = "<html><head><title id='t'>HP &amp; Co.\n LaserJet</title></head>";
        assert_eq!(extract_title(html), Some("HP & Co. LaserJet".into()));
    }

    #[test]
    fn no_title_returns_none() {
        assert_eq!(extract_title("<html><head></head></html>"), None);
    }
}
