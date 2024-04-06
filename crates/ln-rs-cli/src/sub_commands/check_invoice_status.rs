use anyhow::Result;
use clap::Args;
use ln_rs::{Ln, Sha256};

#[derive(Args)]
pub struct CheckInvoiceStatusSubcommand {
    payment_hash: Sha256,
}

pub async fn check_invoice_status(
    sub_command_args: &CheckInvoiceStatusSubcommand,
    ln: Ln,
) -> Result<()> {
    let invoice_status = ln
        .ln_processor
        .check_invoice_status(&sub_command_args.payment_hash)
        .await
        .unwrap();

    println!("{}", invoice_status.to_string());

    Ok(())
}
