use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    os::unix::fs::OpenOptionsExt,
};

use clap::Parser;
use tokio::{net::UdpSocket, sync::RwLock};
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
    rr::rdata::{A, AAAA},
    serialize::binary::{BinEncoder, BinEncodable, BinDecodable},
};

use std::net::ToSocketAddrs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
enum IPAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

type OverrideMap = HashMap<(Name, RecordType), IPAddr>;
type SharedMap = Arc<RwLock<OverrideMap>>;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "overrides.txt")]
    overrides: String,

    #[arg(long, default_value = "0.0.0.0:53")]
    bind: String,

    #[arg(short, long, use_value_delimiter = true)]
    forward: Vec<String>,

    #[arg(long)]
    debug: bool,
}

fn log_request(debug: bool, src: SocketAddr, domain: &str, result: &str) {
    if !debug {
        return;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let line = format!("{}\t{}\t{}\t{}\n", now, src.ip(), domain, result);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o666)
        .open("dnsd.log")
    {
        let _ = file.write_all(line.as_bytes());
    }
}

fn load_overrides(path: &str) -> OverrideMap {
    let file = File::open(path).expect("Failed to open override file");
    let reader = BufReader::new(file);
    let mut map = OverrideMap::new();

    for (i, line) in reader.lines().enumerate() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() != 3 {
                eprintln!("Line {} malformed: '{}'", i + 1, line);
                continue;
            }

            let domain = format!("{}.", parts[0].trim_end_matches('.'));
            let name = match Name::from_str(&domain) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Invalid domain '{}': {}", domain, e);
                    continue;
                }
            };

            let rtype = match parts[1] {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                _ => continue,
            };

            let ip = match rtype {
                RecordType::A => match parts[2].parse() {
                    Ok(ip) => IPAddr::V4(ip),
                    Err(_) => continue,
                },
                RecordType::AAAA => match parts[2].parse() {
                    Ok(ip) => IPAddr::V6(ip),
                    Err(_) => continue,
                },
                _ => continue,
            };

            map.insert((name, rtype), ip);
        }
    }

    map
}

// Try exact + wildcard match for requested type
// If AAAA requested, fallback to A if available
fn match_override(map: &OverrideMap, name: &Name, qtype: RecordType) -> Option<(IPAddr, RecordType)> {
    if let Some(ip) = lookup_override(map, name, qtype) {
        return Some((ip, qtype));
    }

    if qtype == RecordType::AAAA {
        if let Some(ip) = lookup_override(map, name, RecordType::A) {
            return Some((ip, RecordType::A)); // fallback
        }
    }

    None
}

fn lookup_override(map: &OverrideMap, name: &Name, qtype: RecordType) -> Option<IPAddr> {
    if let Some(ip) = map.get(&(name.clone(), qtype)) {
        return Some(ip.clone());
    }

    let labels = name.iter().collect::<Vec<_>>();
    for i in 1..labels.len() {
        let mut wildcard_labels: Vec<&[u8]> = vec![b"*"];
        wildcard_labels.extend_from_slice(&labels[i..]);

        if let Ok(wildcard) = Name::from_labels(wildcard_labels) {
            if let Some(ip) = map.get(&(wildcard, qtype)) {
                return Some(ip.clone());
            }
        }
    }

    None
}

async fn forward_query(forwarders: &[String], packet: &[u8]) -> Option<(Vec<u8>, String)> {
    for server in forwarders {
        if let Ok(mut addrs) = format!("{}:53", server).to_socket_addrs() {
            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                    let _ = sock.send_to(packet, addr).await;
                    let mut buf = [0u8; 512];
                    if let Ok((n, _)) = sock.recv_from(&mut buf).await {
                        return Some((buf[..n].to_vec(), server.clone()));
                    }
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let overrides: SharedMap = Arc::new(RwLock::new(load_overrides(&args.overrides)));
    let forwarders = Arc::new(args.forward);
    let socket = Arc::new(UdpSocket::bind(&args.bind).await?);

    println!("Listening on {}", args.bind);

    loop {
        let mut buf = [0u8; 512];
        let (len, src) = socket.recv_from(&mut buf).await?;
        let req_data = buf[..len].to_vec();

        handle_request(
            req_data,
            src,
            overrides.clone(),
            forwarders.clone(),
            socket.clone(),
            args.overrides.clone(),
            args.debug,
        ).await;
    }
}

async fn handle_request(
    req_data: Vec<u8>,
    src: SocketAddr,
    overrides: SharedMap,
    forwarders: Arc<Vec<String>>,
    socket: Arc<UdpSocket>,
    path: String,
    debug: bool,
) {
    if let Ok(req) = Message::from_vec(&req_data) {
        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_recursion_desired(true);
        resp.set_recursion_available(true);
        resp.add_queries(req.queries().to_vec());

        // Hot reload support
        if req.queries().iter().any(|q| q.name().to_ascii() == "reload.dns.") {
            let mut map = overrides.write().await;
            *map = load_overrides(&path);
            println!("Reloaded overrides.");
            resp.set_response_code(ResponseCode::NoError);
        } else {
            let map = overrides.read().await;
            let mut matched = Vec::new();

            for query in req.queries() {
                if debug {
    println!(
        "DEBUG: Received query [{}] for [{}] from {}",
        query.query_type(),
        query.name().to_ascii(),
        src.ip()
    );
}

             //   if let Some((ip, rtype)) = match_override(&map, query.name(), query.query_type()) {
            if let Some((ip, rtype)) = match_override(&map, query.name(), query.query_type()).or_else(|| match_override(&map, query.name(), RecordType::A)) {
                    let mut rec = Record::new();
                    rec.set_name(query.name().clone());
                    rec.set_record_type(rtype);
                    rec.set_ttl(60);
                    match ip {
                        IPAddr::V4(addr) => rec.set_data(Some(RData::A(A(addr)))),
                        IPAddr::V6(addr) => rec.set_data(Some(RData::AAAA(AAAA(addr)))),
                    };
                    matched.push((query.name().to_ascii(), rec));
                }
            }

            if !matched.is_empty() {
                for (domain, record) in matched {
                    log_request(debug, src, &format!("{} ({:?})", domain, record.record_type()), "override");
                    resp.add_answer(record);
                }

                let mut resp_buf = Vec::new();
                let mut encoder = BinEncoder::new(&mut resp_buf);
                if resp.emit(&mut encoder).is_ok() {
                    let _ = socket.send_to(&resp_buf, src).await;
                }
                return;
            }
        }

        // No override match → forward
        if let Some((response, server)) = forward_query(&forwarders, &req_data).await {
            log_request(debug, src, &req.queries()[0].name().to_ascii(), &server);
            let _ = socket.send_to(&response, src).await;
            return;
        }

        // Forward failed → SERVFAIL
        resp.set_response_code(ResponseCode::ServFail);
        let mut resp_buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut resp_buf);
        if resp.emit(&mut encoder).is_ok() {
            let _ = socket.send_to(&resp_buf, src).await;
        }
    }
}
