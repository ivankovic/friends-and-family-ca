/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
use std::thread;

use super::*;

/// Limits small enough for tests to reach in a fraction of a second.
const LIMITS: Limits = Limits {
    workers: 2,
    queue: 2,
    read: Duration::from_millis(300),
    write: Duration::from_millis(300),
    head: 1024,
    body: 4096,
};

/// A server on a free port, answering with `handler`, and its address. It runs until the test
/// process ends.
fn start(
    limits: Limits,
    handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler: Arc<Handler> = Arc::new(handler);
    thread::spawn(move || serve(listener, limits, handler));
    address
}

/// Answers with the request's method, target and user agent.
fn echo(request: &Request) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type", "text/plain".to_owned())],
        body: format!(
            "{} {} {}",
            request.method,
            request.target,
            request.header("user-agent").unwrap_or("-")
        )
        .into_bytes(),
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

/// Everything the server sends back, until it closes.
fn read_all(stream: &mut TcpStream) -> String {
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

/// Sends `request` on a new connection and returns the whole answer.
fn ask(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = connect(address);
    stream.write_all(request).unwrap();
    read_all(&mut stream)
}

fn status(answer: &str) -> &str {
    answer.get(9..12).unwrap_or(answer)
}

#[test]
fn answers_a_get_and_a_post_and_closes() {
    let address = start(LIMITS, echo);
    let answer = ask(
        address,
        b"GET /x?y HTTP/1.0\r\nHost: k\r\nUser-Agent: Test/1\r\n\r\n",
    );
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains("\r\nConnection: close\r\n"), "{answer}");
    assert!(answer.contains("\r\nContent-Length: 15\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nGET /x?y Test/1"), "{answer}");

    // A body arriving after its head, as a slow client sends it, is read and dropped.
    let mut stream = connect(address);
    stream
        .write_all(b"POST /i/t HTTP/1.1\nContent-Length: 5\n\n")
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    stream.write_all(b"hello").unwrap();
    let answer = read_all(&mut stream);
    assert!(answer.ends_with("POST /i/t -"), "{answer}");
}

#[test]
fn refuses_what_is_not_http_or_is_too_big() {
    let address = start(LIMITS, echo);
    let long_header = format!("GET / HTTP/1.1\r\nX-A: {}\r\n\r\n", "a".repeat(2000));
    for (request, expected) in [
        ("GARBAGE\r\n\r\n", "400"),
        ("GET x HTTP/1.1\r\n\r\n", "400"),
        ("GET / HTTP/2.0\r\n\r\n", "400"),
        ("get / HTTP/1.1\r\n\r\n", "400"),
        ("GET / HTTP/1.1\r\nX-A: a\r\n b\r\n\r\n", "400"),
        ("GET / HTTP/1.1\r\nNo colon\r\n\r\n", "400"),
        (
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            "411",
        ),
        ("POST / HTTP/1.1\r\nContent-Length: 99999\r\n\r\n", "413"),
        ("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", "400"),
        (
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            "400",
        ),
        (long_header.as_str(), "431"),
    ] {
        let answer = ask(address, request.as_bytes());
        assert_eq!(status(&answer), expected, "{request:?} -> {answer}");
    }
}

/// A header line that never ends is cut off at the limit; the server does not keep reading it.
#[test]
fn an_endless_header_line_is_cut_off() {
    let address = start(LIMITS, echo);
    let mut stream = connect(address);
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nX-A: ").unwrap();
    let chunk = [b'a'; 1024];
    let mut sent: usize = 0;
    let error = loop {
        match stream.write(&chunk) {
            Ok(n) => sent += n,
            Err(e) => break e,
        }
        assert!(sent < 64 * 1024 * 1024, "the server kept reading");
    };
    assert!(
        !matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "the server stopped reading but kept the connection: {error}"
    );
    assert!(status(&ask(address, b"GET / HTTP/1.1\r\n\r\n")) == "200");
}

/// Requests pipelined on one connection, their answers never read, get one answer between them,
/// and nobody else waits on them.
#[test]
fn pipelined_requests_do_not_hold_up_others() {
    let address = start(LIMITS, echo);
    let mut greedy = connect(address);
    let requests = b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n".repeat(2000);
    greedy.write_all(&requests).unwrap();
    for _ in 0..5 {
        let started = Instant::now();
        assert_eq!(status(&ask(address, b"GET / HTTP/1.1\r\n\r\n")), "200");
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    let answer = read_all(&mut greedy);
    assert_eq!(answer.matches("HTTP/1.1 ").count(), 1, "{answer}");
}

/// A request trickling in a byte at a time is given up at the deadline, and its worker answers
/// the next one.
#[test]
fn a_slow_request_is_given_up_and_frees_its_worker() {
    let address = start(
        Limits {
            workers: 1,
            ..LIMITS
        },
        echo,
    );
    let mut slow = connect(address);
    slow.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let mut trickle = slow.try_clone().unwrap();
    thread::spawn(move || {
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(100));
            if trickle.write_all(b"X").is_err() {
                return;
            }
        }
    });
    thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    assert_eq!(status(&ask(address, b"GET / HTTP/1.1\r\n\r\n")), "200");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(read_all(&mut slow), "", "closed without an answer");
}

/// Connections that fill every worker and the queue are closed or given up, and the server
/// answers again once they are.
#[test]
fn a_full_queue_recovers() {
    let address = start(
        Limits {
            workers: 1,
            queue: 1,
            ..LIMITS
        },
        echo,
    );
    let idle: Vec<TcpStream> = (0..8).map(|_| connect(address)).collect();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            if stream.write_all(b"GET /healthz HTTP/1.0\r\n\r\n").is_ok()
                && status(&read_all(&mut stream)) == "200"
            {
                break;
            }
        }
        assert!(Instant::now() < deadline, "the server never answered again");
        thread::sleep(Duration::from_millis(50));
    }
    drop(idle);
}

#[test]
fn a_handler_that_panics_gives_a_500_and_its_worker_carries_on() {
    let address = start(
        Limits {
            workers: 1,
            ..LIMITS
        },
        |request| {
            if request.target == "/panic" {
                panic!("a test's panic");
            }
            echo(request)
        },
    );
    for _ in 0..3 {
        assert_eq!(status(&ask(address, b"GET /panic HTTP/1.1\r\n\r\n")), "500");
        assert_eq!(status(&ask(address, b"GET / HTTP/1.1\r\n\r\n")), "200");
    }
}

#[test]
fn a_header_that_could_break_a_line_is_left_out() {
    let response = Response {
        status: 200,
        headers: vec![
            ("X-Ok", "fine".to_owned()),
            ("X-Bad", "a\r\nSet-Cookie: x".to_owned()),
        ],
        body: b"b".to_vec(),
    };
    let text = String::from_utf8(encode(&response)).unwrap();
    assert_eq!(
        text,
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\nX-Ok: fine\r\n\r\nb"
    );
}
