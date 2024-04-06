use std::str::FromStr;

use anyhow::Result;
use clap::Args;
use ln_rs::{Ln, Sha256};
use ln_rs_models::Amount;

#[derive(Args)]
pub struct GetInvoiceSubcommand {
    amount: u64,
    hash: String,
    description: String,
}

pub async fn get_invoice(sub_command_args: &GetInvoiceSubcommand, ln: Ln) -> Result<()> {
    let amount = Amount::from_sat(sub_command_args.amount);
    let hash = Sha256::from_str(&sub_command_args.hash)?;

    let invoice_info = ln
        .ln_processor
        .get_invoice(amount, hash, &sub_command_args.description)
        .await
        .unwrap();

    println!("{}", invoice_info.invoice);

    Ok(())
}
