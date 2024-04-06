use anyhow::Result;
use clap::Args;
use ln_rs::LnProcessor;
use ln_rs_models::Amount;

#[derive(Args)]
pub struct CreateInvoiceSubcommand {
    amount: u64,
    description: String,
}

pub async fn create_invoice<L>(sub_command_args: &CreateInvoiceSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let response = ln
        .create_invoice(
            Amount::from_sat(sub_command_args.amount),
            sub_command_args.description.clone(),
        )
        .await
        .unwrap();

    println!("{}", response.to_string());

    Ok(())
}
