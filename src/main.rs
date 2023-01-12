#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::{io, process};

use clap::Parser;
use serde::{Serialize, Deserialize};
use serde_json;

use radius::core::rfc3580::TUNNEL_TYPE_VLAN;
use radius::core::tag::Tag;
use sha2::{Sha256, Digest};
use base64;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::signal;

use std::fs::File;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::core::packet::Packet;
use radius::core::rfc2865::{lookup_user_password, lookup_nas_identifier};
use radius::core::rfc2868::{
    add_tunnel_password,
    add_tunnel_medium_type,
    add_tunnel_type,
    add_tunnel_private_group_id,
    TUNNEL_MEDIUM_TYPE_IEEE_802,
};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

use hex;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(default_value_t = ("::").to_owned(), short, long)]
    address: String,
    #[arg(default_value_t = 1812, short, long)]
    port: u16,
    conf_file_path: String
}

type NASIds = HashMap<
    String,
    HashMap<
        String,
        Option<PwdConfig>
    >
>;

#[derive(Deserialize, Serialize)]
struct ConfigFile {
    nas_ids: NASIds,
    secret: String
}

#[derive(Deserialize, Serialize)]
struct PwdConfig {
    ppsk_byte_len: Option<usize>,
    vlan_id: Option<u16>
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    let config: ConfigFile = serde_json::from_reader(
        File::open(args.conf_file_path).unwrap()
    ).unwrap();

    // start UDP listening
    let mut server = match Server::listen(
        &args.address,
        args.port,
        MyRequestHandler { nas_ids: config.nas_ids },
        MySecretProvider { secret: config.secret.into_bytes() }
    ).await {
        Ok(server) => server,
        Err(err) => {
            error!("Failed to start server: {}", err.to_string());
            process::exit(1);
        }
    };
    server.set_buffer_size(1500); // default value: 1500
    server.set_skip_authenticity_validation(false); // default value: false

    // once it has reached here, a RADIUS server is now ready
    info!(
        "Server is now ready: {}",
        server.get_listen_address().unwrap()
    );

    // start the loop to handle the RADIUS requests
    if let Err(err) = server.run(signal::ctrl_c()).await {
        error!("Failed to close server {}", err.to_string());
        process::exit(1);
    } else {
        info!("Exit");
    }
}

type MACAddr = [u8; 6];

fn parse_mac_address(addr: &Vec<u8>) -> Option<MACAddr> {
    let result = hex::decode(&addr[..]).ok()?;
    result.try_into().ok()
}

fn get_ppsk(master_pwd: &String, mac: &MACAddr, bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(master_pwd.as_bytes());
    hasher.update(mac);
    let hashed = hasher.finalize();
    let (trunc, _) = hashed.split_at(bytes);
    base64::encode(&trunc)
}

fn get_mac_from_request(req: &Packet) -> Option<(String, Option<MACAddr>)> {
    let mac_vec = lookup_user_password(req)?.ok()?;
    let mac_str = String::from_utf8(mac_vec.clone()).ok()?;
    Some((mac_str, parse_mac_address(&mac_vec)))
}

struct MyRequestHandler {
    nas_ids: NASIds
}

fn add_tunnel_info(vlan_id: Option<u16>, ppsk: &String, tag: &Tag, resp: &mut Packet) {
    let to_sized = |message: &[u8]| [vec![message.len() as u8], message.to_vec()].concat();
    add_tunnel_password(resp, Some(&tag), &to_sized(&ppsk.as_bytes())[..]).unwrap();
    if let Some(vlan_id) = vlan_id {
        add_tunnel_type(resp, Some(&tag), TUNNEL_TYPE_VLAN);
        add_tunnel_medium_type(resp, Some(&tag), TUNNEL_MEDIUM_TYPE_IEEE_802);
        add_tunnel_private_group_id(resp, Some(&tag), &vlan_id.to_string().as_str());
    }
}

fn answer_packet(handler: &MyRequestHandler, req: &Packet) -> Result<Packet, String> {
    let nas_id = match lookup_nas_identifier(req) {
        None => {
            return Err("Request has no nas identifier".to_string());
        },
        Some(Err(error)) => {
            return Err(format!("Failed to read nas identifier: {}", error.to_string()));
        },
        Some(Ok(id)) => {
            id
        }
    };
    let (mac_str, mac_addr) = match get_mac_from_request(req) {
        Some((mac_str, None)) => {
            return Err(format!("Failed to parse MAC address {mac_str:?}"));
        },
        None => {
            return Err("Failed to get MAC address from request".to_string());
        },
        Some((mac_str, Some(mac_addr))) => (mac_str, mac_addr)
    };
    let nas_passwords = handler.nas_ids.get(&nas_id)
        .ok_or(format!("Unidentified nas id {nas_id:?}"))?;

    let mut resp = req.make_response_packet(Code::AccessAccept);
    info!("serving PPSK for station {mac_str}");
    for (tag, (master_pwd, config)) in nas_passwords.iter().enumerate() {
        let config = config.as_ref().unwrap_or(&PwdConfig { ppsk_byte_len: None, vlan_id: None });
        let ppsk_byte_len = config.ppsk_byte_len.unwrap_or(12);

        let ppsk = get_ppsk(master_pwd, &mac_addr, ppsk_byte_len);
        add_tunnel_info(config.vlan_id, &ppsk, &Tag::new(tag as u8), &mut resp);
    }
    Ok(resp)
}

#[async_trait]
impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {

        let req_packet = req.get_packet();

        let resp = answer_packet(&self, &req_packet).unwrap_or_else(|err| {
            error!("{}", err);
            req_packet.make_response_packet(Code::AccessReject)
        });

        conn.send_to(
            &resp.encode().unwrap(),
            req.get_remote_addr(),
        )
        .await?;
        Ok(())
    }
}

struct MySecretProvider {
    secret: Vec<u8>
}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(self.secret.clone())
    }
}
