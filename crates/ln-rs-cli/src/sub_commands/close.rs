use std::str::FromStr;

use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use clap::Args;
use ln_rs::Ln;

#[derive(Args)]
pub struct CloseSubcommand {
    channel_id: String,
    peer_id: Option<String>,
}

pub async fn close(sub_command_args: &CloseSubcommand, ln: Ln) -> Result<()> {
    let peer_id = sub_command_args
        .peer_id
        .clone()
        .map(|p| PublicKey::from_str(&p).unwrap());

    ln.ln_processor
        .close(sub_command_args.channel_id.clone(), peer_id)
        .await
        .unwrap();

    println!("Closing: {}", sub_command_args.channel_id);

    Ok(())
}
