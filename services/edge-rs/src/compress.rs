//! Response compression, backend (Cloud) mode only, like Cloudflare: a compressible response that is
//! not encoded yet leaves the edge as `br` or `gzip` when the client's `Accept-Encoding` allows it.
//!
//! It sits in one place, `proxy::handle`, after the request has been answered, so the response cache
//! and the static asset path keep storing and serving identity bytes (precompressed asset variants
//! carry a `Content-Encoding` and are never touched again). The decision is a pure function of the
//! response (`eligible`) and of the request (`pick_coding`), and is table-tested below.
//!
//! What is compressed: a response with a status that has a body (not 1xx, 204, 205, 206, 304), no
//! `Content-Encoding` (identity counts as none), no `Content-Range`, no `Upgrade`, no
//! `Cache-Control: no-transform`, a compressible `Content-Type` (text, JSON, JavaScript, XML, SVG,
//! WebAssembly, uncompressed font formats; never `text/event-stream`) and, when the length is
//! known, at least `MIN_BYTES`. Never a HEAD response or a ranged request (the offsets would mean
//! the identity bytes).
//!
//! What changes on the way out: `Content-Encoding`, `Vary: Accept-Encoding` (added to every eligible
//! response, also when this client got identity, so a shared cache keys on it), a strong `ETag`
//! becomes weak (the bytes differ from the identity representation), `Content-Length` and
//! `Accept-Ranges` are dropped (the body is chunked now). Trailers are dropped.
//!
//! Streaming: a body of unknown length (a streamed response) is flushed after every upstream chunk,
//! so a slow producer's first chunk still reaches the client at once; a body of known length is
//! left to the encoder's own blocks.
//!
//! Memory: gzip level 5 (miniz_oxide) and brotli quality 4 with a 256 KiB window (lgwin 18); the
//! encoders hold about 350 KiB (gzip) and 2 MiB (brotli) each, measured with a counting allocator on a
//! 3 MB JSON body in 64 KiB chunks. At most `MAX_STREAMS` (16) bodies are compressed at once, so at
//! most about 32 MiB: over that a response goes out as identity, which keeps the cost bounded under
//! the Cloud edge unit's 128M cap. `SPROUTBOAT_EDGE_COMPRESS=off` turns it all off.

use crate::body::{BoxError, RBody};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode};
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// A known length below this is not worth an encoding header (Cloudflare skips tiny bodies too).
pub const MIN_BYTES: u64 = 256;
/// Bodies compressed at the same time, process-wide.
pub const MAX_STREAMS: usize = 16;
const GZIP_LEVEL: u32 = 5;
const BROTLI_QUALITY: u32 = 4;
const BROTLI_LGWIN: u32 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Br,
    Gzip,
}

impl Coding {
    fn token(self) -> &'static str {
        match self {
            Coding::Br => "br",
            Coding::Gzip => "gzip",
        }
    }
}

/// The coding to use for an `Accept-Encoding` value: the one with the higher q, `br` on a tie, a
/// coding that is not listed taking the `*` entry's q, q=0 meaning "not acceptable".
pub fn pick_coding(accept: Option<&str>) -> Option<Coding> {
    let accept = accept?;
    let (mut br, mut gzip, mut star): (Option<f64>, Option<f64>, Option<f64>) = (None, None, None);
    for item in accept.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let q = parts
            .find_map(|p| {
                let (k, v) = p.trim().split_once('=')?;
                k.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| v.trim().parse::<f64>().ok())
                    .flatten()
            })
            .unwrap_or(1.0);
        match name.as_str() {
            "br" => br = Some(q),
            "gzip" | "x-gzip" => gzip = Some(q),
            "*" => star = Some(q),
            _ => {}
        }
    }
    let br = br.or(star).unwrap_or(0.0);
    let gzip = gzip.or(star).unwrap_or(0.0);
    if br > 0.0 && br >= gzip {
        Some(Coding::Br)
    } else if gzip > 0.0 {
        Some(Coding::Gzip)
    } else {
        None
    }
}

/// A `Content-Type` that gains from compression. Formats that are compressed already (images other
/// than SVG, ICO and BMP, video, audio, WOFF, zip) are not on the list.
pub fn compressible_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if essence == "text/event-stream" {
        return false;
    }
    if essence.starts_with("text/") || essence.ends_with("+json") || essence.ends_with("+xml") {
        return true;
    }
    matches!(
        essence.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/x-ndjson"
            | "application/wasm"
            | "application/vnd.ms-fontobject"
            | "application/x-font-ttf"
            | "font/ttf"
            | "font/otf"
            | "font/eot"
            | "image/svg+xml"
            | "image/x-icon"
            | "image/vnd.microsoft.icon"
            | "image/bmp"
    )
}

fn known_length<B: Body>(headers: &HeaderMap, body: &B) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or_else(|| body.size_hint().exact())
}

/// Whether this response could be compressed for some client. Independent of the request, so the
/// `Vary` it earns is the same for every client.
pub fn eligible<B: Body>(res: &Response<B>) -> bool {
    let status = res.status();
    if status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT
                | StatusCode::RESET_CONTENT
                | StatusCode::PARTIAL_CONTENT
                | StatusCode::NOT_MODIFIED
        )
    {
        return false;
    }
    let h = res.headers();
    if h.contains_key("content-range") || h.contains_key("upgrade") {
        return false;
    }
    let encoded = h.get_all("content-encoding").iter().any(|v| {
        v.to_str().map_or(true, |s| {
            !s.trim().eq_ignore_ascii_case("identity") && !s.trim().is_empty()
        })
    });
    if encoded {
        return false;
    }
    let no_transform = h.get_all("cache-control").iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',')
                .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
        })
    });
    if no_transform {
        return false;
    }
    let Some(content_type) = h.get("content-type").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if !compressible_type(content_type) {
        return false;
    }
    known_length(h, res.body()).is_none_or(|n| n >= MIN_BYTES)
}

/// `Vary: Accept-Encoding`, merged into what is there (a `*` or an existing entry stays as it is).
fn add_vary(headers: &mut HeaderMap) {
    let current = headers
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    let listed = current.split(',').any(|t| {
        let t = t.trim();
        t == "*" || t.eq_ignore_ascii_case("accept-encoding")
    });
    if listed {
        return;
    }
    let value = if current.trim().is_empty() {
        "accept-encoding".to_string()
    } else {
        format!("{current}, accept-encoding")
    };
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert("vary", v);
    }
}

fn weaken_etag(headers: &mut HeaderMap) {
    if let Some(value) = headers.get("etag").and_then(|v| v.to_str().ok()) {
        if !value.starts_with("W/") {
            if let Ok(weak) = HeaderValue::from_str(&format!("W/{value}")) {
                headers.insert("etag", weak);
            }
        }
    }
}

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// One of the `MAX_STREAMS` slots; given back on drop.
struct Slot(&'static AtomicUsize);

impl Slot {
    fn try_take() -> Option<Slot> {
        Slot::try_take_from(&ACTIVE, MAX_STREAMS)
    }

    fn try_take_from(counter: &'static AtomicUsize, max: usize) -> Option<Slot> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(counter))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Compress `res` for this request if the rules above allow it. Everything else passes through
/// untouched, except that an eligible response always gets `Vary: Accept-Encoding`.
pub fn apply(
    res: Response<RBody>,
    accept: Option<&str>,
    method: &Method,
    ranged: bool,
) -> Response<RBody> {
    if !eligible(&res) {
        return res;
    }
    let (mut parts, body) = res.into_parts();
    add_vary(&mut parts.headers);
    let coding = match pick_coding(accept) {
        Some(c) if method != Method::HEAD && !ranged => c,
        _ => return Response::from_parts(parts, body),
    };
    let Some(permit) = Slot::try_take() else {
        return Response::from_parts(parts, body);
    };
    let flush_each = known_length(&parts.headers, &body).is_none();
    parts.headers.remove("content-length");
    parts.headers.remove("accept-ranges");
    parts.headers.remove("content-md5");
    weaken_etag(&mut parts.headers);
    parts
        .headers
        .insert("content-encoding", HeaderValue::from_static(coding.token()));
    let body = CompressBody {
        inner: body,
        enc: Some(Encoder::new(coding)),
        flush_each,
        _permit: permit,
    };
    Response::from_parts(parts, body.boxed_unsync())
}

enum Encoder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Br(Box<brotli::CompressorWriter<Vec<u8>>>),
}

impl Encoder {
    fn new(coding: Coding) -> Encoder {
        match coding {
            Coding::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(GZIP_LEVEL),
            )),
            Coding::Br => Encoder::Br(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                BROTLI_QUALITY,
                BROTLI_LGWIN,
            ))),
        }
    }

    /// Feed one chunk; what the encoder has produced so far comes back (maybe nothing).
    fn push(&mut self, data: &[u8], flush: bool) -> Bytes {
        match self {
            Encoder::Gzip(e) => {
                let _ = e.write_all(data);
                if flush {
                    let _ = e.flush();
                }
                Bytes::from(std::mem::take(e.get_mut()))
            }
            Encoder::Br(e) => {
                let _ = e.write_all(data);
                if flush {
                    let _ = e.flush();
                }
                Bytes::from(std::mem::take(e.get_mut()))
            }
        }
    }

    /// End of the body: the rest of the stream, with its trailer.
    fn finish(self) -> Bytes {
        match self {
            Encoder::Gzip(e) => Bytes::from(e.finish().unwrap_or_default()),
            Encoder::Br(e) => Bytes::from(e.into_inner()),
        }
    }
}

/// The compressed body. Its size is unknown (hyper frames it as chunked), whatever the inner
/// body's hint says.
struct CompressBody {
    inner: RBody,
    enc: Option<Encoder>,
    flush_each: bool,
    _permit: Slot,
}

impl Body for CompressBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if this.enc.is_none() {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers are dropped: the encoded body has its own end.
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let out = this
                        .enc
                        .as_mut()
                        .map(|e| e.push(&data, this.flush_each))
                        .unwrap_or_default();
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(out))));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    this.enc = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    let tail = this.enc.take().map(Encoder::finish).unwrap_or_default();
                    return if tail.is_empty() {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Ok(Frame::data(tail))))
                    };
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.enc.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::body::full;
    use crate::config::Config;
    use crate::logs::LogSink;
    use crate::reload::Loaded;
    use crate::routes::Routes;
    use std::io::Read;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn res(status: u16, headers: &[(&str, &str)], body: &'static [u8]) -> Response<RBody> {
        let mut r = Response::new(full(body));
        *r.status_mut() = StatusCode::from_u16(status).unwrap();
        for (k, v) in headers {
            r.headers_mut().append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        r
    }

    const BIG: &[u8] = &[b'a'; 4096];

    #[test]
    fn the_coding_follows_accept_encoding() {
        use Coding::*;
        let table: &[(Option<&str>, Option<Coding>)] = &[
            (None, None),
            (Some(""), None),
            (Some("identity"), None),
            (Some("deflate, zstd"), None),
            (Some("gzip"), Some(Gzip)),
            (Some("GZIP"), Some(Gzip)),
            (Some("x-gzip"), Some(Gzip)),
            (Some("br"), Some(Br)),
            (Some("gzip, deflate, br"), Some(Br)),
            (Some("gzip, br;q=0.5"), Some(Gzip)),
            (Some("br;q=0.5, gzip;q=0.8"), Some(Gzip)),
            (Some("br;q=0, gzip"), Some(Gzip)),
            (Some("br;q=0, gzip;q=0"), None),
            (Some("gzip;q=0"), None),
            (Some("*"), Some(Br)),
            (Some("*;q=0"), None),
            (Some("gzip, *;q=0"), Some(Gzip)),
            (Some("identity, *;q=0.5"), Some(Br)),
            (Some("br ; q = 1.0 , gzip;q=1"), Some(Br)),
            (Some("gzip;q=garbage"), Some(Gzip)),
        ];
        for (accept, want) in table {
            assert_eq!(pick_coding(*accept), *want, "{accept:?}");
        }
    }

    #[test]
    fn only_types_that_gain_are_compressible() {
        for t in [
            "text/html",
            "text/html; charset=utf-8",
            "TEXT/CSS",
            "text/plain",
            "application/json",
            "application/json; charset=utf-8",
            "application/javascript",
            "text/javascript",
            "application/manifest+json",
            "application/ld+json",
            "application/xml",
            "application/atom+xml",
            "image/svg+xml",
            "application/wasm",
            "font/ttf",
            "image/x-icon",
        ] {
            assert!(compressible_type(t), "{t}");
        }
        for t in [
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "image/png",
            "image/jpeg",
            "image/webp",
            "font/woff2",
            "font/woff",
            "video/mp4",
            "audio/mpeg",
            "application/zip",
            "application/gzip",
            "application/octet-stream",
            "application/pdf",
            "",
        ] {
            assert!(!compressible_type(t), "{t}");
        }
    }

    #[test]
    fn what_is_eligible_for_compression() {
        let ct = ("content-type", "text/html");
        assert!(eligible(&res(200, &[ct], BIG)));
        assert!(eligible(&res(404, &[ct], BIG)));
        assert!(eligible(&res(500, &[ct], BIG)));
        // a known length below the threshold, by header or by the body's own size
        assert!(!eligible(&res(200, &[ct], b"tiny")));
        assert!(!eligible(&res(200, &[ct, ("content-length", "255")], BIG)));
        assert!(eligible(&res(200, &[ct, ("content-length", "256")], BIG)));
        // statuses without a body, ranges, upgrades
        for status in [100, 101, 204, 205, 206, 304] {
            assert!(!eligible(&res(status, &[ct], BIG)), "{status}");
        }
        assert!(!eligible(&res(
            200,
            &[ct, ("content-range", "bytes 0-9/100")],
            BIG
        )));
        assert!(!eligible(&res(200, &[ct, ("upgrade", "websocket")], BIG)));
        // already encoded (by anyone), identity is not an encoding
        assert!(!eligible(&res(
            200,
            &[ct, ("content-encoding", "gzip")],
            BIG
        )));
        assert!(!eligible(&res(200, &[ct, ("content-encoding", "br")], BIG)));
        assert!(!eligible(&res(
            200,
            &[ct, ("content-encoding", "zstd")],
            BIG
        )));
        assert!(eligible(&res(
            200,
            &[ct, ("content-encoding", "identity")],
            BIG
        )));
        // no-transform
        assert!(!eligible(&res(
            200,
            &[ct, ("cache-control", "public, No-Transform")],
            BIG
        )));
        assert!(eligible(&res(
            200,
            &[ct, ("cache-control", "public, max-age=0")],
            BIG
        )));
        // type
        assert!(!eligible(&res(
            200,
            &[("content-type", "text/event-stream")],
            BIG
        )));
        assert!(!eligible(&res(200, &[("content-type", "image/png")], BIG)));
        assert!(!eligible(&res(200, &[], BIG)));
    }

    async fn collect(res: Response<RBody>) -> (hyper::http::response::Parts, Vec<u8>) {
        let (parts, body) = res.into_parts();
        (parts, body.collect().await.unwrap().to_bytes().to_vec())
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn unbrotli(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::Decompressor::new(bytes, 4096)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn text_body() -> Vec<u8> {
        (0..400)
            .flat_map(|i| format!("line {i} of a compressible page\n").into_bytes())
            .collect()
    }

    fn leak(v: Vec<u8>) -> &'static [u8] {
        Box::leak(v.into_boxed_slice())
    }

    #[tokio::test]
    async fn gzip_and_brotli_round_trip_and_the_headers_say_so() {
        let original = text_body();
        for (accept, coding) in [("gzip", "gzip"), ("br, gzip", "br"), ("*", "br")] {
            let r = res(
                200,
                &[
                    ("content-type", "text/html; charset=utf-8"),
                    ("content-length", &original.len().to_string()),
                    ("etag", "\"abc\""),
                    ("accept-ranges", "bytes"),
                    ("vary", "Origin"),
                    ("x-keep", "1"),
                ],
                leak(original.clone()),
            );
            let (parts, body) = collect(apply(r, Some(accept), &Method::GET, false)).await;
            let h = &parts.headers;
            assert_eq!(h["content-encoding"], coding);
            assert!(!h.contains_key("content-length"));
            assert!(!h.contains_key("accept-ranges"));
            assert_eq!(h["etag"], "W/\"abc\"");
            assert_eq!(h["vary"], "Origin, accept-encoding");
            assert_eq!(h["x-keep"], "1");
            assert_eq!(h["content-type"], "text/html; charset=utf-8");
            assert!(
                body.len() < original.len() / 4,
                "{} of {}",
                body.len(),
                original.len()
            );
            let back = if coding == "gzip" {
                gunzip(&body)
            } else {
                unbrotli(&body)
            };
            assert_eq!(back, original, "{coding}");
        }
    }

    #[tokio::test]
    async fn a_weak_etag_and_an_existing_vary_entry_stay_as_they_are() {
        let r = res(
            200,
            &[
                ("content-type", "application/json"),
                ("etag", "W/\"x\""),
                ("vary", "Accept-Encoding"),
            ],
            BIG,
        );
        let (parts, _) = collect(apply(r, Some("gzip"), &Method::GET, false)).await;
        assert_eq!(parts.headers["etag"], "W/\"x\"");
        assert_eq!(parts.headers.get_all("vary").iter().count(), 1);
        assert_eq!(parts.headers["vary"], "Accept-Encoding");
        let r = res(
            200,
            &[("content-type", "application/json"), ("vary", "*")],
            BIG,
        );
        let (parts, _) = collect(apply(r, Some("gzip"), &Method::GET, false)).await;
        assert_eq!(parts.headers["vary"], "*");
    }

    #[tokio::test]
    async fn a_client_without_a_usable_coding_gets_identity_with_vary() {
        for accept in [
            None,
            Some("identity"),
            Some("gzip;q=0, br;q=0"),
            Some("zstd"),
        ] {
            let r = res(
                200,
                &[("content-type", "text/css"), ("etag", "\"abc\"")],
                BIG,
            );
            let (parts, body) = collect(apply(r, accept, &Method::GET, false)).await;
            assert_eq!(body, BIG, "{accept:?}");
            assert!(!parts.headers.contains_key("content-encoding"));
            assert_eq!(parts.headers["vary"], "accept-encoding");
            assert_eq!(
                parts.headers["etag"], "\"abc\"",
                "a strong ETag stays strong for identity"
            );
        }
    }

    #[tokio::test]
    async fn head_and_ranged_requests_are_left_alone_but_still_vary() {
        let r = res(200, &[("content-type", "text/html")], BIG);
        let (parts, _) = collect(apply(r, Some("gzip"), &Method::HEAD, false)).await;
        assert!(!parts.headers.contains_key("content-encoding"));
        assert_eq!(parts.headers["vary"], "accept-encoding");
        let r = res(200, &[("content-type", "text/html")], BIG);
        let (parts, body) = collect(apply(r, Some("gzip"), &Method::GET, true)).await;
        assert!(!parts.headers.contains_key("content-encoding"));
        assert_eq!(body, BIG);
    }

    #[tokio::test]
    async fn ineligible_responses_pass_through_untouched() {
        for r in [
            res(
                200,
                &[("content-type", "text/html"), ("content-encoding", "br")],
                BIG,
            ),
            res(
                206,
                &[
                    ("content-type", "text/html"),
                    ("content-range", "bytes 0-4095/9000"),
                ],
                BIG,
            ),
            res(304, &[("content-type", "text/html")], b""),
            res(200, &[("content-type", "text/event-stream")], BIG),
            res(
                200,
                &[("content-type", "image/png"), ("etag", "\"p\"")],
                BIG,
            ),
            res(200, &[("content-type", "text/html")], b"small"),
            res(
                200,
                &[
                    ("content-type", "text/html"),
                    ("cache-control", "no-transform"),
                ],
                BIG,
            ),
        ] {
            let before = r.headers().clone();
            let (parts, body) = collect(apply(r, Some("gzip, br"), &Method::GET, false)).await;
            assert_eq!(parts.headers, before);
            assert!(body == BIG || body == b"small" || body.is_empty());
        }
    }

    /// A body that hands out what a channel receives, with an unknown length.
    fn channel_body() -> (tokio::sync::mpsc::UnboundedSender<Vec<u8>>, RBody) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|chunk| (Ok::<_, BoxError>(Frame::data(Bytes::from(chunk))), rx))
        });
        (tx, http_body_util::StreamBody::new(stream).boxed_unsync())
    }

    #[tokio::test]
    async fn a_streamed_body_is_flushed_per_chunk_so_the_first_chunk_does_not_wait() {
        for accept in ["gzip", "br"] {
            let (tx, body) = channel_body();
            let mut r = Response::new(body);
            r.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            let r = apply(r, Some(accept), &Method::GET, false);
            assert!(!r.headers().contains_key("content-length"));
            let (_, mut body) = r.into_parts();
            let first = "x".repeat(300).into_bytes();
            tx.send(first.clone()).unwrap();
            // The second chunk is not sent yet: the first one must come out on its own.
            let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
                .await
                .unwrap_or_else(|_| panic!("{accept}: the first chunk waited for the second"))
                .unwrap()
                .unwrap();
            let head = frame.into_data().unwrap();
            assert!(!head.is_empty());
            let second = "y".repeat(300).into_bytes();
            tx.send(second.clone()).unwrap();
            drop(tx);
            let mut all = head.to_vec();
            while let Some(frame) = body.frame().await {
                all.extend_from_slice(&frame.unwrap().into_data().unwrap());
            }
            let back = if accept == "gzip" {
                gunzip(&all)
            } else {
                unbrotli(&all)
            };
            assert_eq!(back, [first, second].concat(), "{accept}");
        }
    }

    #[tokio::test]
    async fn the_compressed_body_never_reports_the_identity_size() {
        let r = res(200, &[("content-type", "text/html")], BIG);
        let r = apply(r, Some("gzip"), &Method::GET, false);
        assert_eq!(r.body().size_hint().exact(), None);
    }

    #[tokio::test]
    async fn an_upstream_error_ends_the_body_with_that_error() {
        let stream = futures_util::stream::iter(vec![
            Ok::<_, BoxError>(Frame::data(Bytes::from(vec![b'z'; 1000]))),
            Err::<Frame<Bytes>, BoxError>("upstream went away".into()),
        ]);
        let mut r = Response::new(http_body_util::StreamBody::new(stream).boxed_unsync());
        r.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
        let r = apply(r, Some("gzip"), &Method::GET, false);
        assert!(r.into_body().collect().await.is_err());
    }

    #[test]
    fn slots_are_bounded_and_given_back() {
        static LOCAL: AtomicUsize = AtomicUsize::new(0);
        let held: Vec<_> = (0..3)
            .map(|_| Slot::try_take_from(&LOCAL, 3).unwrap())
            .collect();
        assert!(Slot::try_take_from(&LOCAL, 3).is_none());
        drop(held);
        assert_eq!(LOCAL.load(Ordering::Acquire), 0);
        assert!(Slot::try_take_from(&LOCAL, 3).is_some());
    }

    // ---- through the real server, in backend mode ----

    /// An upstream that answers every request with `reply` (raw head + body), keep-alive off.
    async fn upstream(reply: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = stream.write_all(&reply).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    async fn edge(backend: SocketAddr, compress: Option<&str>) -> SocketAddr {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("routes.json").display().to_string();
        let compress = compress.map(str::to_string);
        let cfg = Config::from_lookup(|n| match n {
            "PORT" => Some("0".into()),
            "SPROUTBOAT_EDGE_BACKEND" => Some(format!("http://{backend}")),
            "SPROUTBOAT_ROUTE_SNAPSHOT" => Some(snapshot.clone()),
            "SPROUTBOAT_EDGE_COMPRESS" => compress.clone(),
            _ => None,
        })
        .unwrap();
        let app = App::new(
            cfg,
            Routes::default(),
            Loaded::default(),
            LogSink::disabled(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(crate::server::serve(app, listener));
        std::mem::forget(dir);
        addr
    }

    /// (status, lower-cased head, body bytes), the body de-chunked.
    async fn get(
        edge: SocketAddr,
        method: &str,
        headers: &[(&str, &str)],
    ) -> (u16, String, Vec<u8>) {
        let mut req =
            format!("{method} /page HTTP/1.1\r\nHost: stale.test\r\nConnection: close\r\n");
        for (k, v) in headers {
            req += &format!("{k}: {v}\r\n");
        }
        req += "\r\n";
        let mut stream = TcpStream::connect(edge).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&raw[..split]).to_lowercase();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        let mut body = raw[split + 4..].to_vec();
        if head.contains("transfer-encoding: chunked") {
            let mut out = Vec::new();
            let mut rest = &body[..];
            loop {
                let eol = rest.windows(2).position(|w| w == b"\r\n").unwrap();
                let size =
                    usize::from_str_radix(std::str::from_utf8(&rest[..eol]).unwrap().trim(), 16)
                        .unwrap();
                rest = &rest[eol + 2..];
                if size == 0 {
                    break;
                }
                out.extend_from_slice(&rest[..size]);
                rest = &rest[size + 2..];
            }
            body = out;
        }
        (status, head, body)
    }

    fn reply(head: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "HTTP/1.1 200 OK\r\n{head}content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    #[tokio::test]
    async fn through_the_edge_a_json_response_is_brotli_for_a_client_that_accepts_it() {
        let original = text_body();
        let backend = upstream(reply(
            "content-type: application/json\r\netag: \"v1\"\r\n",
            &original,
        ))
        .await;
        let edge = edge(backend, None).await;
        let (status, head, body) =
            get(edge, "GET", &[("Accept-Encoding", "gzip, deflate, br")]).await;
        assert_eq!(status, 200);
        assert!(head.contains("content-encoding: br"), "{head}");
        assert!(head.contains("vary: accept-encoding"), "{head}");
        assert!(head.contains("etag: w/\"v1\""), "{head}");
        assert!(!head.contains("content-length"), "{head}");
        assert_eq!(unbrotli(&body), original);
        let (_, head, body) = get(edge, "GET", &[("Accept-Encoding", "gzip")]).await;
        assert!(head.contains("content-encoding: gzip"), "{head}");
        assert_eq!(gunzip(&body), original);
        let (_, head, body) = get(edge, "GET", &[]).await;
        assert!(!head.contains("content-encoding"), "{head}");
        assert!(head.contains("vary: accept-encoding"), "{head}");
        assert!(head.contains("etag: \"v1\""), "{head}");
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn through_the_edge_an_encoded_upstream_and_a_range_are_not_touched() {
        let original = text_body();
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&original).unwrap();
            e.finish().unwrap()
        };
        let backend = upstream(reply(
            "content-type: text/html\r\ncontent-encoding: gzip\r\n",
            &gz,
        ))
        .await;
        let edge1 = edge(backend, None).await;
        let (_, head, body) = get(edge1, "GET", &[("Accept-Encoding", "br, gzip")]).await;
        assert!(head.contains("content-encoding: gzip"), "{head}");
        assert!(!head.contains("vary"), "{head}");
        assert_eq!(
            body, gz,
            "an already encoded body passes through byte for byte"
        );

        let backend = upstream(reply("content-type: text/html\r\n", &original)).await;
        let edge2 = edge(backend, None).await;
        let (_, head, body) = get(
            edge2,
            "GET",
            &[("Accept-Encoding", "gzip"), ("Range", "bytes=0-9")],
        )
        .await;
        assert!(!head.contains("content-encoding"), "{head}");
        assert_eq!(body, original);
        let (_, head, body) = get(edge2, "HEAD", &[("Accept-Encoding", "gzip")]).await;
        assert!(!head.contains("content-encoding"), "{head}");
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn the_switch_turns_it_off_and_community_mode_never_compresses() {
        let original = text_body();
        let backend = upstream(reply("content-type: text/html\r\n", &original)).await;
        let off = edge(backend, Some("off")).await;
        let (_, head, body) = get(off, "GET", &[("Accept-Encoding", "gzip")]).await;
        assert!(!head.contains("content-encoding"), "{head}");
        assert!(!head.contains("vary"), "{head}");
        assert_eq!(body, original);
        let community = Config::from_lookup(|n| (n == "PORT").then(|| "0".into())).unwrap();
        assert!(!community.compress);
        assert!(
            Config::from_lookup(|n| match n {
                "SPROUTBOAT_EDGE_BACKEND" => Some("http://127.0.0.1:8600".into()),
                _ => None,
            })
            .unwrap()
            .compress
        );
    }
}
