use std::{collections::HashMap, fs::File, net::{Ipv4Addr, Ipv6Addr}, str::FromStr, sync::Arc};
use std::io::{BufRead, BufReader};
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::rr::rdata::{A, AAAA};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use tokio::sync::RwLock;
use clap::Parser;
use std::net::ToSocketAddrs;

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
}

fn load_overrides(path: &str) -> OverrideMap {
    let file = File::open(path).expect("Failed to open overrides file");
    let reader = BufReader::new(file);

    let mut map = HashMap::new();

    for line in reader.lines() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() != 3 {
                continue;
            }

            let domain = Name::from_str(parts[0]).unwrap();
            let record_type = match parts[1] {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                _ => continue,
            };

            let ip = match record_type {
                RecordType::A => IPAddr::V4(parts[2].parse().unwrap()),
                RecordType::AAAA => IPAddr::V6(parts[2].parse().unwrap()),
                _ => continue,
            };

            map.insert((domain, record_type), ip);
        }
    }

    map
}

async fn forward_query(forwarders: &[String], request: &[u8]) -> Option<Vec<u8>> {
    for server in forwarders {
        if let Ok(addr_iter) = format!("{}:53", server).to_socket_addrs() {
            for addr in addr_iter {
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
                    if socket.send_to(request, &addr).await.is_ok() {
                        let mut buf = vec![0u8; 512];
                        if let Ok((len, _)) = socket.recv_from(&mut buf).await {
                            return Some(buf[..len].to_vec());
                        }
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

    let overrides: SharedMap = if args.usecache {
        Arc::new(RwLock::new(load_overrides(&args.overrides)))
    } else {
        Arc::new(RwLock::new(HashMap::new()))
    };

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
        let usecache = args.usecache;
        let path = args.overrides.clone();

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
                        if usecache {
                            let mut map = overrides.write().await;
                            *map = load_overrides(&path);
                            println!("Overrides cache reloaded via reload.dns query.");
                        }
                        resp.set_response_code(ResponseCode::NoError);
                        let mut resp_buf = Vec::new();
                        let mut encoder = BinEncoder::new(&mut resp_buf);
                        if resp.emit(&mut encoder).is_ok() {
                            let _ = socket.send_to(&resp_buf, &src).await;
                        }
                        return;
                    }

                    let map = if usecache {
                        overrides.read().await.clone()
                    } else {
                        load_overrides(&path)
                    };

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
                    }
                }

                if !found && !forwarders.is_empty() {
                    if let Some(response) = forward_query(&forwarders, &req_data).await {
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
