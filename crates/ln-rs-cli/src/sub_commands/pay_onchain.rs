use std::str::FromStr;

use anyhow::Result;
use bitcoin::Address;
use clap::Args;
use ln_rs::Ln;
use ln_rs_models::Amount;

#[derive(Args)]
pub struct PayOnChainSubcommand {
    address: String,
    amount: u64,
}

pub async fn pay_onchain(sub_command_args: &PayOnChainSubcommand, ln: Ln) -> Result<()> {
    let pay_response = ln
        .ln_processor
        .pay_on_chain(
            Address::from_str(&sub_command_args.address)
                .unwrap()
                // TODO: Check
                .assume_checked(),
            Amount::from_sat(sub_command_args.amount),
        )
        .await
        .unwrap();

    println!("{}", pay_response);

    Ok(())
}
