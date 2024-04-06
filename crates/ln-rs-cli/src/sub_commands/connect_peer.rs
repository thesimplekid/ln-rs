use std::str::FromStr;

use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use clap::Args;
use ln_rs::LnProcessor;

#[derive(Args)]
pub struct ConnectPeerSubcommand {
    public_key: String,
    host: String,
    port: u16,
}

pub async fn connect_peer<L>(sub_command_args: &ConnectPeerSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let public_key = PublicKey::from_str(&sub_command_args.public_key).unwrap();

    let response = ln
        .connect_peer(
            public_key,
            sub_command_args.host.clone(),
            sub_command_args.port,
        )
        .await
        .unwrap();

    println!("{:?}", response);

    Ok(())
}
