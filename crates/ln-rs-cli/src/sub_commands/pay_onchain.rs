use std::str::FromStr;

use anyhow::Result;
use bitcoin::Address;
use clap::Args;
use ln_rs::LnProcessor;
use ln_rs_models::Amount;

#[derive(Args)]
pub struct PayOnChainSubcommand {
    address: String,
    amount: u64,
}

pub async fn pay_onchain<L>(sub_command_args: &PayOnChainSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let pay_response = ln
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
