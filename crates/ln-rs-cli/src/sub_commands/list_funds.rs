use anyhow::Result;
use clap::Args;
use ln_rs::Ln;

#[derive(Args)]
pub struct ListFundsSubcommand {}

pub async fn list_funds(_sub_command_args: &ListFundsSubcommand, ln: Ln) -> Result<()> {
    let c = ln.ln_processor.get_balance().await.unwrap();

    println!("{:?}", c);

    Ok(())
}
