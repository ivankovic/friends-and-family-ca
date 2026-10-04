/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
//! The page's HTTP server: as much of HTTP/1.x as nginx in front of it uses.
//!
//! nginx sends one request per connection, with its body already buffered, so the server reads
//! one request, answers it and closes. What it guards against is a client that reaches the port
//! directly, past nginx and its limits:
//!
//! * A fixed set of worker threads takes connections from a bounded queue. A connection that finds
//!   the queue full is closed at once. The thread that accepts connections never reads or writes
//!   one, so no client can hold it up.
//! * Each request must arrive whole within [`Limits::read`] of a worker taking it, however slowly
//!   it trickles in. Writes time out after [`Limits::write`].
//! * The request line and headers are at most [`Limits::head`] bytes; a body, sent with
//!   `Content-Length`, at most [`Limits::body`]. The body is read and dropped: the page takes no
//!   input but the address. Chunked bodies are refused.
//! * Anything after the request - pipelined requests - is never read as one.
//! * A handler that panics gives a 500. Its worker carries on.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// How much the server takes from a client.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Threads answering requests.
    pub workers: usize,
    /// Connections waiting for a worker; beyond, a new one is closed.
    pub queue: usize,
    /// How long a request may take to arrive whole.
    pub read: Duration,
    /// How long writing the answer may block.
    pub write: Duration,
    /// The longest request line and headers, in bytes.
    pub head: usize,
    /// The longest body, in bytes.
    pub body: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            workers: 16,
            queue: 64,
            read: Duration::from_secs(10),
            write: Duration::from_secs(10),
            head: 16 * 1024,
            body: 64 * 1024,
        }
    }
}

/// How long a closed connection's leftover input is read and dropped, at most: see [`linger`].
const LINGER: Duration = Duration::from_secs(1);

/// A request: its line and headers. The body has been read and dropped.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The path, with its query, as sent.
    pub target: String,
    pub headers: Vec<(String, String)>,
    /// The address the connection comes from.
    pub peer: SocketAddr,
}

impl Request {
    /// The value of the first header called `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An answer. `Content-Length` and `Connection: close` are added to its headers.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A short plain-text answer.
    pub fn plain(status: u16) -> Response {
        Response {
            status,
            headers: vec![("Content-Type", "text/plain".to_owned())],
            body: format!("{status} {}\n", reason(status)).into_bytes(),
        }
    }
}

/// What answers a request.
pub type Handler = dyn Fn(&Request) -> Response + Send + Sync;

/// Answers connections on `listener` with `handler`, until the process ends.
pub fn serve(listener: TcpListener, limits: Limits, handler: Arc<Handler>) -> Result<()> {
    if limits.workers == 0 {
        bail!("the page needs at least one worker");
    }
    let (queue, waiting) = mpsc::sync_channel::<TcpStream>(limits.queue);
    let waiting = Arc::new(Mutex::new(waiting));
    for n in 0..limits.workers {
        let (waiting, handler) = (waiting.clone(), handler.clone());
        std::thread::Builder::new()
            .name(format!("ffca-worker-{n}"))
            .spawn(move || work(&waiting, handler.as_ref(), limits))
            .context("cannot start the page's workers")?;
    }
    loop {
        match listener.accept() {
            Ok((stream, _)) => match queue.try_send(stream) {
                Ok(()) => {}
                // Every worker is busy and the queue is full: closed unanswered, at once.
                Err(TrySendError::Full(stream)) => drop(stream),
                Err(TrySendError::Disconnected(_)) => bail!("the page's workers have stopped"),
            },
            // Out of file descriptors, say: waiting a moment frees some, and keeps the loop from
            // spinning.
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// A worker: answers connections from `waiting`, one at a time, until the queue is gone.
fn work(waiting: &Mutex<Receiver<TcpStream>>, handler: &Handler, limits: Limits) {
    loop {
        // The lock is released at the end of this statement, before the connection is answered.
        let next = waiting.lock().unwrap_or_else(|p| p.into_inner()).recv();
        let Ok(stream) = next else { return };
        // A failure here is the client's: it went away, was too slow, or sent nonsense.
        let _ = connection(stream, handler, limits);
    }
}

/// Why a request is not handed to the handler.
enum Refused {
    /// An answer it gets instead: the request is malformed or too big.
    Answer(u16),
    /// None: the client went away or is too slow.
    Gone(io::Error),
}

impl From<io::Error> for Refused {
    fn from(error: io::Error) -> Refused {
        Refused::Gone(error)
    }
}

/// Reads one request from `stream`, answers it and closes.
fn connection(mut stream: TcpStream, handler: &Handler, limits: Limits) -> io::Result<()> {
    let started = Instant::now();
    let deadline = started.checked_add(limits.read).unwrap_or(started);
    stream.set_write_timeout(Some(limits.write))?;
    let peer = stream.peer_addr()?;
    let response = match read_request(&mut stream, peer, deadline, limits) {
        Ok(request) => catch_unwind(AssertUnwindSafe(|| handler(&request)))
            .unwrap_or_else(|_| Response::plain(500)),
        Err(Refused::Answer(status)) => Response::plain(status),
        Err(Refused::Gone(error)) => return Err(error),
    };
    stream.write_all(&encode(&response))?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    linger(&mut stream, limits.read.min(LINGER));
    Ok(())
}

/// Reads what is left of the client's input for up to `time`, until it closes its side.
///
/// Closing a connection with input unread makes the kernel reset it, and a reset can destroy the
/// answer before the client has read it - a request refused for its size has the most left.
fn linger(stream: &mut TcpStream, time: Duration) {
    let started = Instant::now();
    let deadline = started.checked_add(time).unwrap_or(started);
    let mut buffer = [0u8; 4096];
    let mut left: usize = 64 * 1024;
    while left > 0 {
        match read_some(stream, &mut buffer, deadline) {
            Ok(n) => left = left.saturating_sub(n),
            Err(_) => return,
        }
    }
}

/// One read from `stream`, given up at `deadline`. The end of input is an error: a request is
/// never complete without more.
fn read_some(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn read_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    deadline: Instant,
    limits: Limits,
) -> Result<Request, Refused> {
    let mut input: Vec<u8> = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    let (head_len, body_start) = loop {
        if let Some(found) = end_of_head(&input) {
            break found;
        }
        if input.len() > limits.head {
            return Err(Refused::Answer(431));
        }
        let n = read_some(stream, &mut buffer, deadline)?;
        input.extend_from_slice(buffer.get(..n).unwrap_or_default());
    };
    if head_len > limits.head {
        return Err(Refused::Answer(431));
    }
    let head = String::from_utf8_lossy(input.get(..head_len).unwrap_or_default());
    let request = parse_head(&head, peer).ok_or(Refused::Answer(400))?;

    if request.header("Transfer-Encoding").is_some() {
        return Err(Refused::Answer(411));
    }
    let mut length: Option<u64> = None;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("Content-Length") {
            let value: u64 = value
                .parse()
                .ok()
                .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(Refused::Answer(400))?;
            if length.is_some_and(|l| l != value) {
                return Err(Refused::Answer(400));
            }
            length = Some(value);
        }
    }
    let length = length.unwrap_or(0);
    if length > limits.body {
        return Err(Refused::Answer(413));
    }
    let mut unread = length.saturating_sub(input.len().saturating_sub(body_start) as u64);
    while unread > 0 {
        let n = read_some(stream, &mut buffer, deadline)?;
        unread = unread.saturating_sub(n as u64);
    }
    Ok(request)
}

/// The length of the request line and headers in `input`, and where the body starts, once the
/// blank line that ends them has arrived. A bare LF is taken for CRLF, as nginx and most servers
/// do.
fn end_of_head(input: &[u8]) -> Option<(usize, usize)> {
    let lf = input.iter().enumerate().filter(|(_, b)| **b == b'\n');
    for (i, _) in lf {
        let before = input.get(..i).unwrap_or_default();
        let blank = match before {
            [.., b'\n', b'\r'] => Some(i.saturating_sub(1)),
            [.., b'\n'] => Some(i),
            _ => None,
        };
        if let Some(end) = blank {
            return Some((end, i.saturating_add(1)));
        }
    }
    None
}

/// The request line and headers, or `None` if they are not HTTP/1.x.
fn parse_head(head: &str, peer: SocketAddr) -> Option<Request> {
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let method_ok =
        (1..=20).contains(&method.len()) && method.bytes().all(|b| b.is_ascii_uppercase());
    let target_ok = target.starts_with('/') && !target.bytes().any(|b| b.is_ascii_control());
    if parts.next().is_some()
        || !method_ok
        || !target_ok
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        // A line starting with white space continues the one before: obsolete, and refused.
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return None;
        }
        headers.push((name.to_owned(), value.trim_matches([' ', '\t']).to_owned()));
    }
    Some(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        peer,
    })
}

/// `response` as HTTP/1.1, closing the connection. A header whose value could break a line is
/// left out.
fn encode(response: &Response) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    for (name, value) in &response.headers {
        if !value.chars().any(|c| c.is_control()) {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&response.body);
    out
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests;
