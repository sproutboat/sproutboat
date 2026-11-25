//! Static assets: the manifest `sproutboat build` writes next to the artifact,
//! and the edge-side matching rules (a faithful port of `@sproutboat/assets`
//! `resolveAssetKey` / `isSproutFirst` / `matchHeaders` / `matchRedirect`,
//! plus `asset-rules.ts` and `asset-cache-control.ts`).

use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct AssetEntry {
    pub hash: String,
    #[allow(dead_code)] // the file on disk decides the length served
    pub size: u64,
    #[serde(rename = "type")]
    pub content_type: String,
    /// Backend mode: precompressed variants (blobs of their own). Community ignores them.
    #[serde(default)]
    pub br: Option<Variant>,
    #[serde(default)]
    pub gz: Option<Variant>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Variant {
    pub hash: String,
    #[allow(dead_code)] // the blob on disk decides the length served
    pub size: u64,
}

/// What a miss does (the manifest's `notFound`). Only backend mode reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotFound {
    #[default]
    None,
    SinglePageApplication,
    Page404,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HeaderRule {
    pub pattern: String,
    #[serde(default)]
    pub set: Vec<(String, String)>,
    #[serde(default)]
    pub unset: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RedirectRule {
    pub from: String,
    pub to: String,
    pub status: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RunSproutFirst {
    All(bool),
    Patterns(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawManifest {
    run_sprout_first: RunSproutFirst,
    /// Left untyped: Community mode never looks at it, so it can never fail a parse there.
    #[serde(default)]
    not_found: Option<serde_json::Value>,
    files: HashMap<String, AssetEntry>,
    #[serde(default)]
    headers: Option<Vec<HeaderRule>>,
    #[serde(default)]
    redirects: Option<Vec<RedirectRule>>,
}

enum SproutFirst {
    All(bool),
    /// (negated, compiled pattern; `None` when the glob is not a valid regex, which never matches)
    Patterns(Vec<(bool, Option<Regex>)>),
}

pub struct Manifest {
    pub files: HashMap<String, AssetEntry>,
    pub headers: Vec<HeaderRule>,
    pub redirects: Vec<RedirectRule>,
    pub not_found: NotFound,
    sprout_first: SproutFirst,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, String> {
        Manifest::parse_with(text, false)
    }

    /// Backend mode: the same format, and `notFound` is honoured (absent means `none`).
    pub fn parse_backend(text: &str) -> Result<Manifest, String> {
        Manifest::parse_with(text, true)
    }

    fn parse_with(text: &str, backend: bool) -> Result<Manifest, String> {
        let raw: RawManifest = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let sprout_first = match raw.run_sprout_first {
            RunSproutFirst::All(b) => SproutFirst::All(b),
            RunSproutFirst::Patterns(list) => SproutFirst::Patterns(
                list.iter()
                    .map(|raw| match raw.strip_prefix('!') {
                        Some(rest) => (true, glob_regex(rest)),
                        None => (false, glob_regex(raw)),
                    })
                    .collect(),
            ),
        };
        let not_found = match (backend, raw.not_found.as_ref()) {
            (false, _) | (true, None) | (true, Some(serde_json::Value::Null)) => NotFound::None,
            (true, Some(serde_json::Value::String(v))) => match v.as_str() {
                "none" => NotFound::None,
                "single-page-application" => NotFound::SinglePageApplication,
                "404-page" => NotFound::Page404,
                other => return Err(format!("unknown notFound: {other}")),
            },
            (true, Some(_)) => return Err("notFound must be a string".to_string()),
        };
        Ok(Manifest {
            files: raw.files,
            headers: raw.headers.unwrap_or_default(),
            redirects: raw.redirects.unwrap_or_default(),
            not_found,
            sprout_first,
        })
    }

    /// Does `pathname` hit the sprout before assets?
    pub fn is_sprout_first(&self, pathname: &str) -> bool {
        match &self.sprout_first {
            SproutFirst::All(b) => *b,
            SproutFirst::Patterns(list) => {
                let mut matched = false;
                for (negate, rx) in list {
                    if rx.as_ref().is_some_and(|rx| rx.is_match(pathname)) {
                        matched = !negate;
                    }
                }
                matched
            }
        }
    }

    pub fn resolve_key(&self, path: &str) -> Option<String> {
        resolve_asset_key(path, |k| self.files.contains_key(k))
    }

    /// The first `_redirects` rule matching `pathname`: (status, location).
    pub fn redirect(&self, pathname: &str) -> Option<(u16, String)> {
        self.redirects
            .iter()
            .find_map(|rule| match_redirect(rule, pathname).map(|loc| (rule.status, loc)))
    }
}

/// Resolve a request path to a manifest key the way a static host does.
pub fn resolve_asset_key(path: &str, has: impl Fn(&str) -> bool) -> Option<String> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.ends_with('/') {
        let index = format!("{path}index.html");
        return has(&index).then_some(index);
    }
    if has(&path) {
        return Some(path);
    }
    let base = &path[path.rfind('/').map_or(0, |i| i + 1)..];
    if !base.contains('.') {
        let html = format!("{path}.html");
        if has(&html) {
            return Some(html);
        }
        let index = format!("{path}/index.html");
        if has(&index) {
            return Some(index);
        }
    }
    None
}

/// The regex source `globMatch` builds: `*` inside a segment, `**` across them.
/// Faithfully keeps the original's quirk that a literal space becomes `.*`.
fn glob_regex(pattern: &str) -> Option<Regex> {
    let mut escaped = String::with_capacity(pattern.len() + 8);
    for c in pattern.chars() {
        if ".+^${}()|[]\\".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    let rx = escaped
        .replace("**", " ")
        .replace('*', "[^/]*")
        .replace(' ', ".*");
    Regex::new(&format!("^{rx}$")).ok()
}

/// `*` matches within a segment, `**` across segments. Anchored both ends.
#[cfg(test)]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    glob_regex(pattern).is_some_and(|rx| rx.is_match(path))
}

/// `_headers` patterns: a trailing `*` segment is greedy across `/`.
fn header_pattern_matches(pattern: &str, pathname: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = pathname.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in pattern_segments.iter().enumerate() {
        if *seg == "*" {
            return true;
        }
        if path_segments.get(i) != Some(seg) {
            return false;
        }
    }
    pattern_segments.len() == path_segments.len()
}

/// Every `_headers` rule whose pattern matches `pathname`, in file order.
pub fn match_headers<'a>(rules: &'a [HeaderRule], pathname: &str) -> Vec<&'a HeaderRule> {
    rules
        .iter()
        .filter(|r| header_pattern_matches(&r.pattern, pathname))
        .collect()
}

/// Match `pathname` against one `_redirects` rule, substituting `:name`
/// segments and a trailing `*` (as `:splat`) into `to`.
pub fn match_redirect(rule: &RedirectRule, pathname: &str) -> Option<String> {
    if let Some(star) = rule.from.find('*') {
        let prefix = &rule.from[..star];
        let splat = pathname.strip_prefix(prefix)?;
        return Some(rule.to.replace(":splat", splat));
    }
    let from_segments: Vec<&str> = rule.from.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = pathname.split('/').filter(|s| !s.is_empty()).collect();
    if from_segments.len() != path_segments.len() {
        return None;
    }
    // Insertion-ordered like a JS object: a repeated name keeps its first position.
    let mut params: Vec<(&str, &str)> = Vec::new();
    for (segment, actual) in from_segments.iter().zip(&path_segments) {
        if let Some(name) = segment.strip_prefix(':') {
            match params.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = actual,
                None => params.push((name, actual)),
            }
            continue;
        }
        if segment != actual {
            return None;
        }
    }
    let mut to = rule.to.clone();
    for (name, value) in params {
        to = to.replace(&format!(":{name}"), value);
    }
    Some(to)
}

/// Does the file name carry a build-tool content hash? Two rules, both on the name only
/// (no directory guesses: `/assets/logo.svg` is a user file, `/_astro/x.css` could be too).
///
/// 1. A `.`/`-`/`_`-delimited piece of 8+ characters that mixes letters with digits
///    (webpack, Next, Vite, Astro hashes that happen to contain a digit).
/// 2. Exactly 8 base64url characters shaped `name.HASH.ext` or `name-HASH.ext`
///    (Astro, Vite, Rolldown). With a digit they must mix upper and lower case (this
///    catches hashes cut up by their own `-`/`_`, as in `DDw8VC-O`). Without a digit (about
///    1 in 5 hashes) they must look random: 3+ upper case, a lower case and 2+ case changes. A word
///    (`document`, `Facebook`, `MyButton`), an acronym (`HTMLView`) or a constant
///    (`OVERVIEW`) fails at least one test. A miss only costs a revalidation.
fn is_fingerprinted(asset_key: &str) -> bool {
    let filename = asset_key.rsplit('/').next().unwrap_or("");
    let digit_token = filename.split(['.', '-', '_']).any(|token| {
        token.chars().count() >= 8
            && token.bytes().any(|b| b.is_ascii_digit())
            && token.bytes().any(|b| b.is_ascii_alphabetic())
    });
    digit_token || has_letters_only_hash(filename.as_bytes())
}

fn has_letters_only_hash(name: &[u8]) -> bool {
    const LEN: usize = 8;
    // delimiter before (with a name in front of it), `.` after (an extension follows)
    (1..name.len().saturating_sub(LEN)).any(|start| {
        matches!(name[start - 1], b'.' | b'-')
            && start >= 2
            && name[start + LEN] == b'.'
            && looks_random(&name[start..start + LEN])
    })
}

fn looks_random(token: &[u8]) -> bool {
    if !token
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return false;
    }
    let digits = token.iter().filter(|b| b.is_ascii_digit()).count();
    let upper = token.iter().filter(|b| b.is_ascii_uppercase()).count();
    let lower = token.iter().filter(|b| b.is_ascii_lowercase()).count();
    if digits > 0 {
        // `DDw8VC-O`: the digit rule again, for hashes whose own `-`/`_` split them up
        return upper >= 1 && lower >= 1;
    }
    let flips = token
        .windows(2)
        .filter(|w| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()
        })
        .count();
    upper + lower >= 6 && upper >= 3 && lower >= 1 && flips >= 2
}

/// `Cache-Control` for an edge-served static asset, Cloudflare Workers static assets semantics:
/// `public, max-age=0, must-revalidate` (the ETag is the content hash, so a revalidation is a
/// 304), and `immutable` only for names we can prove carry a content hash.
pub fn cache_control_for(asset_key: &str) -> &'static str {
    if is_fingerprinted(asset_key) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=0, must-revalidate"
    }
}

/// `Cache-Control` in backend mode: the same policy (a page may change under a stable name,
/// and so may any other file).
pub fn cache_control_backend(asset_key: &str, _content_type: &str) -> &'static str {
    cache_control_for(asset_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(from: &str, to: &str) -> RedirectRule {
        RedirectRule {
            from: from.into(),
            to: to.into(),
            status: 302,
        }
    }

    #[test]
    fn fingerprinted_names_are_immutable() {
        let forever = "public, max-age=31536000, immutable";
        for key in [
            "/_astro/index.Ke7awTe2.css",
            "/assets/index-a1b2c3d4.js",
            "/static/js/main.8f3a2b1c.chunk.js",
            "/_next/static/chunks/main.a1b2c3d4.js",
            "/_app/immutable/chunks/0.b2c3d4e5.js",
            "/_nuxt/entry.c3d4e5f6.js",
        ] {
            assert_eq!(cache_control_for(key), forever, "{key}");
        }
    }

    #[test]
    fn backend_html_revalidates() {
        let html = "text/html; charset=utf-8";
        assert_eq!(
            cache_control_backend("/ikada/index.html", html),
            "public, max-age=0, must-revalidate"
        );
        assert_eq!(
            cache_control_backend("/a", "TEXT/HTML"),
            "public, max-age=0, must-revalidate"
        );
        assert_eq!(
            cache_control_backend("/logo.svg", "image/svg+xml"),
            "public, max-age=0, must-revalidate"
        );
        assert_eq!(
            cache_control_backend("/_astro/index.Ke7awTe2.css", "text/css"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control_backend("/page.a1b2c3d4.html", html),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn not_found_is_read_in_backend_mode_only() {
        let text = |nf: &str| {
            format!(
                r#"{{"notFound":{nf},"runSproutFirst":false,"files":{{"/a":{{"hash":"h","size":1,"type":"t","br":{{"hash":"b","size":1}}}}}}}}"#
            )
        };
        assert_eq!(
            Manifest::parse_backend(&text(r#""404-page""#))
                .unwrap()
                .not_found,
            NotFound::Page404
        );
        assert_eq!(
            Manifest::parse_backend(&text(r#""single-page-application""#))
                .unwrap()
                .not_found,
            NotFound::SinglePageApplication
        );
        assert_eq!(
            Manifest::parse_backend(&text(r#""none""#))
                .unwrap()
                .not_found,
            NotFound::None
        );
        assert!(Manifest::parse_backend(&text(r#""sometimes""#)).is_err());
        assert!(Manifest::parse_backend(&text("3")).is_err());
        let absent = r#"{"runSproutFirst":false,"files":{}}"#;
        assert_eq!(
            Manifest::parse_backend(absent).unwrap().not_found,
            NotFound::None
        );
        // Community never reads it, so it cannot fail there.
        let m = Manifest::parse(&text("3")).unwrap();
        assert_eq!(m.not_found, NotFound::None);
        assert_eq!(
            m.files["/a"].br.as_ref().map(|v| v.hash.as_str()),
            Some("b")
        );
        assert!(m.files["/a"].gz.is_none());
    }

    #[test]
    fn plain_names_revalidate() {
        for key in [
            "/fonts/bricolage-grotesque-latin.woff2",
            "/fonts/jetbrains-mono-latin.woff2",
            "/favicon.svg",
            "/logo.svg",
            "/og/home.png",
            "/robots.txt",
            "/app.css",
        ] {
            assert_eq!(
                cache_control_for(key),
                "public, max-age=0, must-revalidate",
                "{key}"
            );
        }
    }

    /// Hashed names from real builds: Astro 5 and Rolldown (site, docs), Vite 7 (cloud
    /// dashboard) and TanStack Start (sproutboat web), all read from `dist` folders on
    /// 2026-11-25, plus the Next.js and webpack/CRA shapes. Letters-only hashes are the
    /// ones the old digit rule missed.
    const HASHED: &[&str] = &[
        // Astro, letters only
        "/_astro/Layout.BQLfoQtT.css",
        "/_astro/Layout.DfzoWvmC.css",
        "/_astro/Layout.DRiDnmKM.css",
        "/_astro/Layout.ByiY2IYt.css",
        "/_astro/Layout.YyuW9mWK.css",
        "/_astro/Layout.DEjbHM9L.css",
        "/_astro/Layout.BjOrbay8.css",
        "/_astro/Docs.8mcaNtnL.css",
        "/_astro/BlockPreview.CYGfpe6A.js",
        "/_astro/CompositeRoot.CtsK4fip.js",
        "/_astro/DialogTitle.CNfq8uXU.js",
        "/_astro/HomeShowcase.CFVGlQ9t.js",
        "/_astro/pure.DtvNgFTA.js",
        "/_astro/page.CZh4tvAt.js",
        "/_astro/scene.BetpJ0YL.js",
        "/_astro/prefetch.ChQ6Rgti.js",
        "/_astro/instrument-serif-italic.DKMiL14s.woff2",
        "/_astro/MessageComposer.astro_astro_type_script_index_0_lang.DDw8VC-O.js",
        "/_astro/PanelTabs.astro_astro_type_script_index_0_lang.CxIN-ILs.js",
        "/_astro/PageActions.astro_astro_type_script_index_0_lang.hIdOPHzl.js",
        "/_astro/Hero.astro_astro_type_script_index_0_lang.zqgYOFP0.js",
        // Astro, with a digit
        "/_astro/_..CMaAEJG5.css",
        "/_astro/chrome-icons.5Dk-A2Gq.js",
        "/_astro/esm.b0x1Q25u.js",
        "/_astro/how.BB7s_qJ3.css",
        "/_astro/validate-json.C6aK2IaD.js",
        "/_astro/WebMcp.astro_astro_type_script_index_0_lang.D9N1Gby_.js",
        // Vite, both kinds
        "/assets/index-DVmHr4mN.css",
        "/assets/index-OQv5BlF8.js",
        "/assets/esm-D8nwNgJn.js",
        "/assets/figtree-latin-wght-normal-D_ZTVpCC.woff2",
        "/assets/jetbrains-mono-latin-wght-normal-B9CIFXIH.woff2",
        "/assets/preload-helper-PMedUJL0.js",
        "/assets/settings.tokens-CvZ6DdJy.js",
        "/assets/projects_._name.deployments-HjljbiU6.js",
        "/assets/admin.users-Z7OKpJPu.js",
        // Next.js, webpack, SvelteKit, Nuxt (hex or digit-bearing)
        "/_next/static/chunks/main-app-4f5a6b7c8d9e0a1b.js",
        "/_next/static/chunks/webpack-5d1c2e3f4a5b6c7d.js",
        "/_next/static/css/5a3b9c1d2e4f6a7b.css",
        "/_next/static/media/e4af272ccee01ff0-s.p.woff2",
        "/static/js/main.8f3a2b1c.chunk.js",
        "/_app/immutable/chunks/0.b2c3d4e5.js",
        "/_nuxt/entry.c3d4e5f6.js",
    ];

    /// Names that must never be called fingerprinted: real public files from the
    /// same builds, plus the ones a naive "mixed case, 8 letters" rule would catch.
    const PLAIN: &[&str] = &[
        "/index.html",
        "/404.html",
        "/favicon.svg",
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/robots.txt",
        "/sitemap.xml",
        "/install.sh",
        "/schema.json",
        "/_headers",
        "/LICENSE",
        "/app.css",
        "/analytics-engine.json",
        "/agent-readability.json",
        "/ai-catalog.json",
        "/chart-wide-dark-1440.webp",
        "/chart-raft-light-390.webp",
        "/fonts/bricolage-grotesque-latin.woff2",
        "/fonts/jetbrains-mono-latin.woff2",
        "/_astro/fonts/jetbrains-mono.woff2",
        "/og/home.png",
        // eight-letter words and names after a delimiter
        "/docs-overview.pdf",
        "/my-document.pdf",
        "/user.profile.json",
        "/logo-Facebook.png",
        "/logo.Facebook.png",
        "/icons/icon-MyButton.svg",
        "/img/hero-HTMLView.png",
        "/docs-OVERVIEW.pdf",
        "/x.UserCard.js",
        "/jquery.minified.js",
        "/react-dom.production.min.js",
        "/jquery-3.7.1.min.js",
        "/v1.2.3/app.js",
        "/en-US.json",
        "/Roboto-Regular.woff2",
        "/Inter-SemiBold.woff2",
        "/NotoSansJP-Regular.otf",
        "/README.md",
        // a directory that looks hashed does not make its files hashed
        "/Layout.BQLfoQtT/logo.svg",
        "/assets/logo.svg",
        "/_astro/logo.svg",
        "/_next/static/logo.png",
    ];

    #[test]
    fn real_build_hashes_are_immutable() {
        let forever = "public, max-age=31536000, immutable";
        for key in HASHED {
            assert_eq!(cache_control_for(key), forever, "{key}");
            assert_eq!(cache_control_backend(key, "text/css"), forever, "{key}");
        }
    }

    #[test]
    fn plain_corpus_is_never_immutable() {
        for key in PLAIN {
            assert_eq!(
                cache_control_for(key),
                "public, max-age=0, must-revalidate",
                "{key}"
            );
        }
    }

    /// Real hashes the rule does not claim: with no digit and a `-`/`_` inside, a hash
    /// like `DBQx-q_a` looks the same as `CSS-Grid`. They revalidate, which is safe.
    #[test]
    fn ambiguous_hashes_stay_revalidating() {
        for key in [
            "/assets/jetbrains-mono-latin-ext-wght-normal-DBQx-q_a.woff2",
            "/assets/projects_._name--ao-MJ-C.js",
            "/assets/root-DLTE-HSj.js",
            "/guide-CSS-Grid.pdf",
        ] {
            assert_eq!(
                cache_control_for(key),
                "public, max-age=0, must-revalidate",
                "{key}"
            );
        }
    }

    #[test]
    fn letters_only_hash_needs_name_and_extension() {
        // a bare token, no name in front or no extension behind, is not a hash
        for key in [
            "/BQLfoQtT.css",
            "/.BQLfoQtT.css",
            "/Layout.BQLfoQtT",
            "/Layout.BQLfoQtTx.css",
        ] {
            assert_eq!(
                cache_control_for(key),
                "public, max-age=0, must-revalidate",
                "{key}"
            );
        }
    }

    #[test]
    fn sprout_first_patterns() {
        let t = |spec: &[&str], path: &str| {
            let list = serde_json::to_string(spec).unwrap();
            Manifest::parse(&format!(
                r#"{{"notFound":"none","runSproutFirst":{list},"files":{{}}}}"#
            ))
            .unwrap()
            .is_sprout_first(path)
        };
        let all = |b: bool| {
            Manifest::parse(&format!(
                r#"{{"notFound":"none","runSproutFirst":{b},"files":{{}}}}"#
            ))
            .unwrap()
        };
        assert!(all(true).is_sprout_first("/anything"));
        assert!(!all(false).is_sprout_first("/anything"));
        assert!(t(&["/api/*"], "/api/users"));
        assert!(!t(&["/api/*"], "/index.html"));
        assert!(!t(&["/api/*", "!/api/docs/*"], "/api/docs/intro"));
        assert!(t(&["/api/**"], "/api/a/b/c"));
        assert!(!t(&["/api/*"], "/api/a/b"));
        // regex metacharacters are escaped
        assert!(!glob_match("/a.b", "/axb"));
        assert!(glob_match("/a.b", "/a.b"));
    }

    #[test]
    fn manifest_sprout_first_matches_free_function() {
        let m = Manifest::parse(
            r#"{"notFound":"none","runSproutFirst":["/api/*","!/api/docs/*"],"files":{}}"#,
        )
        .unwrap();
        assert!(m.is_sprout_first("/api/users"));
        assert!(!m.is_sprout_first("/api/docs/intro"));
        assert!(!m.is_sprout_first("/index.html"));
    }

    #[test]
    fn resolve_keys() {
        let files = [
            "/index.html",
            "/docs.html",
            "/guide/index.html",
            "/a.css",
            "/blog/index.html",
        ];
        let has = |k: &str| files.contains(&k);
        assert_eq!(resolve_asset_key("/", has).as_deref(), Some("/index.html"));
        assert_eq!(
            resolve_asset_key("/docs", has).as_deref(),
            Some("/docs.html")
        );
        assert_eq!(
            resolve_asset_key("/guide", has).as_deref(),
            Some("/guide/index.html")
        );
        assert_eq!(
            resolve_asset_key("/guide/", has).as_deref(),
            Some("/guide/index.html")
        );
        assert_eq!(resolve_asset_key("/a.css", has).as_deref(), Some("/a.css"));
        assert_eq!(resolve_asset_key("/a.js", has), None);
        assert_eq!(resolve_asset_key("/nope/", has), None);
        assert_eq!(
            resolve_asset_key("docs", has).as_deref(),
            Some("/docs.html")
        );
    }

    #[test]
    fn redirects() {
        assert_eq!(
            match_redirect(&rule("/old", "/new"), "/old").as_deref(),
            Some("/new")
        );
        assert_eq!(match_redirect(&rule("/old", "/new"), "/old/extra"), None);
        assert_eq!(match_redirect(&rule("/old", "/new"), "/other"), None);
        let user = rule("/user/:id", "/profile/:id");
        assert_eq!(
            match_redirect(&user, "/user/42").as_deref(),
            Some("/profile/42")
        );
        assert_eq!(match_redirect(&user, "/user"), None);
        assert_eq!(match_redirect(&user, "/user/42/extra"), None);
        let blog = rule("/blog/*", "/articles/:splat");
        assert_eq!(
            match_redirect(&blog, "/blog/2024/hello").as_deref(),
            Some("/articles/2024/hello")
        );
        assert_eq!(
            match_redirect(&blog, "/blog/").as_deref(),
            Some("/articles/")
        );
        assert_eq!(match_redirect(&blog, "/blog"), None);
    }

    fn manifest() -> Manifest {
        let mut m = Manifest::parse(r#"{"notFound":"none","runSproutFirst":false,"files":{"/new.html":{"hash":"h","size":1,"type":"text/html"}}}"#).unwrap();
        m.redirects = vec![
            RedirectRule {
                from: "/new.html".into(),
                to: "/elsewhere".into(),
                status: 301,
            },
            RedirectRule {
                from: "/blog/:slug".into(),
                to: "/posts/:slug".into(),
                status: 302,
            },
            RedirectRule {
                from: "/docs/*".into(),
                to: "https://docs.example.com/:splat".into(),
                status: 308,
            },
        ];
        m.headers = vec![
            HeaderRule {
                pattern: "/*".into(),
                set: vec![
                    ("x-frame-options".into(), "DENY".into()),
                    ("cache-control".into(), "no-store".into()),
                ],
                unset: vec![],
            },
            HeaderRule {
                pattern: "/public/*".into(),
                set: vec![("cache-control".into(), "public, max-age=60".into())],
                unset: vec!["x-frame-options".into()],
            },
        ];
        m
    }

    #[test]
    fn first_matching_redirect_wins_even_over_a_file() {
        let m = manifest();
        assert_eq!(m.redirect("/new.html"), Some((301, "/elsewhere".into())));
        assert_eq!(
            m.redirect("/blog/hello"),
            Some((302, "/posts/hello".into()))
        );
        assert_eq!(
            m.redirect("/docs/a/b"),
            Some((308, "https://docs.example.com/a/b".into()))
        );
        assert_eq!(m.redirect("/blog/a/b"), None);
    }

    #[test]
    fn header_rules_match_in_file_order() {
        let m = manifest();
        let names = |p: &str| {
            match_headers(&m.headers, p)
                .iter()
                .map(|r| r.pattern.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names("/a.css"), ["/*"]);
        assert_eq!(names("/public/x/y.png"), ["/*", "/public/*"]);
        assert_eq!(names("/"), ["/*"]);
        let rules = vec![HeaderRule {
            pattern: "/exact".into(),
            set: vec![],
            unset: vec![],
        }];
        assert_eq!(match_headers(&rules, "/exact").len(), 1);
        assert_eq!(match_headers(&rules, "/exact/more").len(), 0);
    }

    #[test]
    fn manifest_parses_what_the_build_writes() {
        let m = Manifest::parse(
            r#"{"notFound":"404-page","runSproutFirst":["/api/**"],"files":{"/a.css":{"hash":"x","size":3,"type":"text/css"}},
               "headers":[{"pattern":"/*","set":[["A","b"]],"unset":["C"]}],"redirects":[{"from":"/o","to":"/n","status":301}]}"#,
        )
        .unwrap();
        assert_eq!(m.files["/a.css"].size, 3);
        assert_eq!(m.headers[0].set, vec![("A".to_string(), "b".to_string())]);
        assert!(Manifest::parse("{}").is_err());
    }
}

/// A single `Range: bytes=...` request resolved against a file of `size` bytes.
#[derive(Debug, PartialEq)]
pub enum ByteRange {
    /// No usable Range header (absent, malformed, or several ranges): serve the whole file.
    Full,
    /// Inclusive start and end.
    Partial(u64, u64),
    Unsatisfiable,
}

pub fn parse_range(header: Option<&str>, size: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((a, b)) = spec.split_once('-') else {
        return ByteRange::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    let num = |s: &str| s.parse::<u64>().ok();
    match (a.is_empty(), b.is_empty()) {
        (true, false) => match num(b) {
            Some(0) | None => ByteRange::Unsatisfiable,
            Some(n) if size == 0 => {
                let _ = n;
                ByteRange::Unsatisfiable
            }
            Some(n) => ByteRange::Partial(size.saturating_sub(n), size - 1),
        },
        (false, empty_end) => {
            let Some(start) = num(a) else {
                return ByteRange::Full;
            };
            let end = if empty_end {
                size.saturating_sub(1)
            } else {
                num(b).map_or(u64::MAX, |e| e.min(size.saturating_sub(1)))
            };
            if start >= size || end < start {
                ByteRange::Unsatisfiable
            } else {
                ByteRange::Partial(start, end)
            }
        }
        _ => ByteRange::Full,
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), ByteRange::Full);
        assert_eq!(parse_range(Some("bytes=0-3"), 10), ByteRange::Partial(0, 3));
        assert_eq!(parse_range(Some("bytes=5-"), 10), ByteRange::Partial(5, 9));
        assert_eq!(parse_range(Some("bytes=-4"), 10), ByteRange::Partial(6, 9));
        assert_eq!(
            parse_range(Some("bytes=8-99"), 10),
            ByteRange::Partial(8, 9)
        );
        assert_eq!(parse_range(Some("bytes=10-"), 10), ByteRange::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-1,4-5"), 10), ByteRange::Full);
        assert_eq!(parse_range(Some("items=0-1"), 10), ByteRange::Full);
    }
}
