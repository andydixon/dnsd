# dnsd

**dnsd** is a lightweight, high-performance DNS server written in Rust. It supports custom domain overrides via a plain text file, in-memory caching, hot reloading, and DNS forwarding to upstream resolvers.

## Features

- Fast, async DNS server using Tokio and trust-dns-proto
- Override DNS responses via a plain text file
- Optional in-memory caching
- Hot reload support (via `reload.dns` query)
- Forward unresolved queries to upstream DNS servers

## Installation

Clone and build with Cargo:

```bash
git clone https://github.com/yourname/dnsd.git
cd dnsd
cargo build --release
```

## Usage

```bash
sudo ./target/release/dnsd [OPTIONS]
```

### Options

| Option         | Description                                          | Example                        |
|----------------|------------------------------------------------------|--------------------------------|
| `--overrides`  | Path to the overrides file                           | `--overrides overrides.txt`    |
| `--usecache`   | Use in-memory caching of overrides                   | `--usecache`                   |
| `--bind`       | IP:PORT to bind the server to                        | `--bind 127.0.0.1:5353`        |
| `--forward`    | Comma-separated list of upstream DNS resolvers       | `--forward 1.1.1.1,8.8.8.8`    |

## Override File Format

The override file should contain one entry per line in the following format:

```
example.com A 1.2.3.4
example.org AAAA 2001:db8::1
```

## Hot Reloading

To trigger a cache reload (if using `--usecache`), perform a DNS lookup for:

```
reload.dns
```

This will flush the cache and reload the override file.

## Example

```bash
sudo ./dnsd \\
  --overrides myhosts.txt \\
  --usecache \\
  --bind 127.0.0.1:5353 \\
  --forward 1.1.1.1,8.8.8.8
```

## Testing

```bash
dig @127.0.0.1 -p 5353 example.com
```