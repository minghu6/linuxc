use std::{
    io::{Read, Result},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
};

use clap::Parser;

/// Handle a single TCP connection.
fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let from_addr = stream.local_addr().unwrap();

    let mut buf = [0; 1024 * 8];

    match stream.read(&mut buf) {
        Ok(nbytes) => {
            println!("Received from {}: {nbytes} bytes\n{}", from_addr, std::str::from_utf8(&buf).unwrap());
        }
        Err(err) => eprintln!("Error from {}: {}", from_addr, err),
    }

    match stream.read(&mut buf) {
        Ok(nbytes) => {
            println!("Received from {}: {nbytes} bytes\n{}", from_addr, std::str::from_utf8(&buf).unwrap());
        }
        Err(err) => eprintln!("Error from {}: {}", from_addr, err),
    }

    stream.shutdown(Shutdown::Write)?;

    Ok(())
}

/// CLI for the TCP server.
#[derive(Parser)]
struct Cli {
    /// IP address to bind to.
    #[arg(default_value_t = Ipv4Addr::new(127, 0, 0, 1))]
    ip: Ipv4Addr,

    /// Port to listen on.
    #[arg(default_value_t = 8888)]
    port: u16,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let sockaddrv4 = SocketAddrV4::new(cli.ip, cli.port);

    // Create a TCP listener
    let listener = TcpListener::bind(sockaddrv4)?;

    println!("Server listening on {}:{}", cli.ip, cli.port);

    // Handle incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_connection(stream)?;
            }
            Err(err) => {
                eprintln!("Error accepting connection: {}", err);
            }
        }
    }

    Ok(())
}
