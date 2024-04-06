use std::str::FromStr;

use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use clap::Args;
use ln_rs::Ln;
use ln_rs_models::requests::OpenChannelRequest;
use ln_rs_models::Amount;

#[derive(Args)]
pub struct OpenChannelSubcommand {
    public_key: String,
    host: String,
    port: u16,
    amount: u64,
    push_amount: Option<u64>,
}

pub async fn open_channel(sub_command_args: &OpenChannelSubcommand, ln: Ln) -> Result<()> {
    let open_channel_request = OpenChannelRequest {
        public_key: PublicKey::from_str(&sub_command_args.public_key)?,
        host: sub_command_args.host.clone(),
        port: sub_command_args.port,
        amount: Amount::from_sat(sub_command_args.amount),
        push_amount: sub_command_args.push_amount.map(|a| Amount::from_sat(a)),
    };

    let response = ln
        .ln_processor
        .open_channel(open_channel_request)
        .await
        .unwrap();

    println!("Open Channel: {}", response);

    Ok(())
}
