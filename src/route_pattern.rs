use crate::tls_client_hello;
use std::io;

pub fn normalize(pattern: &str) -> io::Result<String> {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return tls_client_hello::normalize_hostname(pattern);
    };
    let suffix = tls_client_hello::normalize_hostname(suffix)?;
    let pattern = format!("*.{suffix}");
    if pattern.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wildcard route pattern is too long",
        ));
    }
    Ok(pattern)
}

pub fn matching_wildcard(hostname: &str) -> Option<String> {
    let hostname = tls_client_hello::normalize_hostname(hostname).ok()?;
    let (_, suffix) = hostname.split_once('.')?;
    Some(format!("*.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::{matching_wildcard, normalize};

    #[test]
    fn normalizes_exact_names_and_whole_leftmost_wildcards() {
        assert_eq!(normalize("WWW.Example.COM.").unwrap(), "www.example.com");
        assert_eq!(normalize("*.Example.COM.").unwrap(), "*.example.com");
        for invalid in [
            "*",
            "*.",
            "*example.com",
            "w*.example.com",
            "**.example.com",
            "*.*.example.com",
            "example.*",
            "*..example.com",
            "*.127.0.0.1",
            "*.bad_name.example",
            "*.-bad.example",
        ] {
            assert!(normalize(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn wildcard_matching_consumes_exactly_one_concrete_label() {
        let pattern = Some("*.example.com".to_string());
        for hostname in ["foo.example.com", "BAR.Example.com."] {
            assert_eq!(matching_wildcard(hostname), pattern);
        }
        for hostname in [
            "example.com",
            "deep.foo.example.com",
            "badexample.com",
            "foo.example.com.evil",
            ".example.com",
            "*.example.com",
            "foo..example.com",
        ] {
            assert_ne!(matching_wildcard(hostname), pattern, "{hostname}");
        }
    }

    #[test]
    fn wildcard_patterns_respect_the_full_dns_name_length_limit() {
        let suffix = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(59)
        );
        assert_eq!(normalize(&format!("*.{suffix}")).unwrap().len(), 253);
        assert!(normalize(&format!("*.{suffix}d")).is_err());
    }
}
