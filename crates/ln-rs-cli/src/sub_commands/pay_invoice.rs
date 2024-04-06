use anyhow::Result;
use clap::Args;
use ln_rs::{Bolt11Invoice, LnProcessor};
use ln_rs_models::Amount;

#[derive(Args)]
pub struct PayInvoiceSubcommand {
    bolt11: Bolt11Invoice,
    max_fee: Option<u64>,
}

pub async fn pay_invoice<L>(sub_command_args: &PayInvoiceSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let max_fee = sub_command_args.max_fee.map(|f| Amount::from_sat(f));

    let pay_response = ln
        .pay_invoice(sub_command_args.bolt11.clone(), max_fee)
        .await
        .unwrap();

    println!("{}", pay_response.status.to_string());

    Ok(())
}
