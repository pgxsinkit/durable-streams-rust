use std::net::SocketAddr;
use std::path::PathBuf;

use durable_streams::access::{run, AccessConfig};
use hyper::Uri;

fn usage() -> ! {
    eprintln!(
        "usage: durable-streams-access \\\n         --server-cert PATH --server-key PATH --client-ca PATH --policy PATH \\\n         [--listen 0.0.0.0:8443] [--upstream http://127.0.0.1:4437]"
    );
    std::process::exit(2)
}

fn value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> String {
    arguments.next().unwrap_or_else(|| {
        eprintln!("error: {flag} requires a value");
        usage()
    })
}

fn parse_config() -> AccessConfig {
    let mut listen = "0.0.0.0:8443"
        .parse::<SocketAddr>()
        .expect("static listen address");
    let mut upstream = "http://127.0.0.1:4437"
        .parse::<Uri>()
        .expect("static upstream URI");
    let mut server_cert = None;
    let mut server_key = None;
    let mut client_ca = None;
    let mut policy = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--listen" => {
                let raw = value(&mut arguments, &flag);
                listen = raw.parse().unwrap_or_else(|error| {
                    eprintln!("error: invalid --listen {raw:?}: {error}");
                    usage()
                });
            }
            "--upstream" => {
                let raw = value(&mut arguments, &flag);
                upstream = raw.parse().unwrap_or_else(|error| {
                    eprintln!("error: invalid --upstream {raw:?}: {error}");
                    usage()
                });
            }
            "--server-cert" => server_cert = Some(PathBuf::from(value(&mut arguments, &flag))),
            "--server-key" => server_key = Some(PathBuf::from(value(&mut arguments, &flag))),
            "--client-ca" => client_ca = Some(PathBuf::from(value(&mut arguments, &flag))),
            "--policy" => policy = Some(PathBuf::from(value(&mut arguments, &flag))),
            "--help" | "-h" => usage(),
            _ => {
                eprintln!("error: unknown argument {flag:?}");
                usage()
            }
        }
    }
    AccessConfig {
        listen,
        upstream,
        server_cert: server_cert.unwrap_or_else(|| {
            eprintln!("error: --server-cert is required");
            usage()
        }),
        server_key: server_key.unwrap_or_else(|| {
            eprintln!("error: --server-key is required");
            usage()
        }),
        client_ca: client_ca.unwrap_or_else(|| {
            eprintln!("error: --client-ca is required");
            usage()
        }),
        policy: policy.unwrap_or_else(|| {
            eprintln!("error: --policy is required");
            usage()
        }),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    if let Err(error) = run(parse_config()).await {
        tracing::error!(error = %error, "durable-streams-access failed");
        std::process::exit(1);
    }
}
