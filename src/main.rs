use std::{collections::HashMap, fs::File, fs::OpenOptions, io::Write, net::{Ipv4Addr, Ipv6Addr, SocketAddr}, str::FromStr, sync::Arc};
use std::io::{BufRead, BufReader};
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::rr::rdata::{A, AAAA};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use tokio::sync::RwLock;
use clap::Parser;
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
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "overrides.txt")]
    overrides: String,

    #[arg(long)]
    usecache: bool,

    #[arg(short, long, default_value = "0.0.0.0:53")]
    bind: String,

    #[arg(short, long, use_value_delimiter = true)]
    forward: Vec<String>,

    #[arg(long)]
    debug: bool,
}

fn load_overrides(path: &str) -> OverrideMap {
    let file = File::open(path).expect("Failed to open overrides file");
    let reader = BufReader::new(file);

    let mut map = HashMap::new();

    for (i, line) in reader.lines().enumerate() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() != 3 {
                eprintln!("[Line {}] Invalid format: '{}'", i + 1, line);
                continue;
            }

            let fqdn = format!("{}.", parts[0].trim_end_matches('.'));
            let domain = match Name::from_str(&fqdn) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("[Line {}] Invalid domain '{}': {}", i + 1, parts[0], e);
                    continue;
                }
            };

            let record_type = match parts[1] {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                _ => {
                    eprintln!("[Line {}] Unsupported record type '{}'", i + 1, parts[1]);
                    continue;
                }
            };

            let ip = match record_type {
                RecordType::A => match parts[2].parse() {
                    Ok(ipv4) => IPAddr::V4(ipv4),
                    Err(e) => {
                        eprintln!("[Line {}] Invalid IPv4 address '{}': {}", i + 1, parts[2], e);
                        continue;
                    }
                },
                RecordType::AAAA => match parts[2].parse() {
                    Ok(ipv6) => IPAddr::V6(ipv6),
                    Err(e) => {
                        eprintln!("[Line {}] Invalid IPv6 address '{}': {}", i + 1, parts[2], e);
                        continue;
                    }
                },
                _ => continue,
            };

            map.insert((domain, record_type), ip);
        }
    }

    map
}

async fn forward_query(forwarders: &[String], request: &[u8]) -> Option<(Vec<u8>, String)> {
    for server in forwarders {
        if let Ok(addr_iter) = format!("{}:53", server).to_socket_addrs() {
            for addr in addr_iter {
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
                    if socket.send_to(request, &addr).await.is_ok() {
                        let mut buf = vec![0u8; 512];
                        if let Ok((len, _)) = socket.recv_from(&mut buf).await {
                            return Some((buf[..len].to_vec(), server.clone()));
                        }
                    }
                }
            }
        }
    }
    None
}

fn log_request(debug: bool, src: SocketAddr, domain: &str, result: &str) {
    if !debug {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let log_line = format!("{}\t{}\t{}\t{}\n", now, src.ip(), domain, result);
    if let Ok(mut file) = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o666)
            .open("dnsd.log")
    }
    {
        let _ = file.write_all(log_line.as_bytes());
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let overrides: SharedMap = Arc::new(RwLock::new(load_overrides(&args.overrides)));
println!("Overrides loaded from {}", args.overrides);

    let socket = Arc::new(UdpSocket::bind(&args.bind).await?);
    println!("DNS server listening on {}", args.bind);

    let forwarders = Arc::new(args.forward);
    let mut buf = vec![0u8; 512];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let req_data = buf[..len].to_vec();
        let overrides = overrides.clone();
        let socket = socket.clone();
        let forwarders = forwarders.clone();
                let path = args.overrides.clone();
        let debug = args.debug;

        tokio::spawn(async move {
            if let Ok(req) = Message::from_bytes(&req_data) {
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                resp.set_recursion_desired(true);
                resp.set_recursion_available(true);
                resp.add_queries(req.queries().to_vec());

                let mut found = false;

                for query in req.queries() {
                    let name = query.name().clone();
                    let qtype = query.query_type();

                    if name.to_ascii().eq_ignore_ascii_case("reload.dns.") {
                            let mut map = overrides.write().await;
                            *map = load_overrides(&path);
                            println!("Overrides cache reloaded via reload.dns query.");
                        resp.set_response_code(ResponseCode::NoError);
                        let mut resp_buf = Vec::new();
                        let mut encoder = BinEncoder::new(&mut resp_buf);
                        if resp.emit(&mut encoder).is_ok() {
                            let _ = socket.send_to(&resp_buf, &src).await;
                        }
                        return;
                    }

                    let map = overrides.read().await.clone();

                    if let Some(ip) = map.get(&(name.clone(), qtype)) {
                        let mut record = Record::new();
                        record.set_name(name.clone());
                        record.set_record_type(qtype);
                        record.set_ttl(60);

                        match ip {
    IPAddr::V4(addr) => record.set_data(Some(RData::A(A(*addr)))),
    IPAddr::V6(addr) => record.set_data(Some(RData::AAAA(AAAA(*addr)))),
};

                        resp.add_answer(record);
                        found = true;

                        log_request(debug, src, &name.to_ascii(), "override");
                    }
                }

                if !found && !forwarders.is_empty() {
                    if let Some((response, server)) = forward_query(&forwarders, &req_data).await {
                        log_request(debug, src, &req.queries()[0].name().to_ascii(), &server);
                        let _ = socket.send_to(&response, &src).await;
                        return;
                    } else {
                        resp.set_response_code(ResponseCode::ServFail);
                    }
                }

                let mut resp_buf = Vec::new();
                let mut encoder = BinEncoder::new(&mut resp_buf);
                if resp.emit(&mut encoder).is_ok() {
                    let _ = socket.send_to(&resp_buf, &src).await;
                }
            }
        });
    }
}
