use anyhow::Result;
use clap::Args;
use ln_rs::{LnProcessor, Sha256};

#[derive(Args)]
pub struct CheckInvoiceStatusSubcommand {
    payment_hash: Sha256,
}

pub async fn check_invoice_status<L>(
    sub_command_args: &CheckInvoiceStatusSubcommand,
    ln: L,
) -> Result<()>
where
    L: LnProcessor,
{
    let invoice_status = ln
        .check_invoice_status(&sub_command_args.payment_hash)
        .await
        .unwrap();

    println!("{}", invoice_status.to_string());

    Ok(())
}
