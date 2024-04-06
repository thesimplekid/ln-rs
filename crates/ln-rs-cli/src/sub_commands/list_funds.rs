use anyhow::Result;
use clap::Args;
use ln_rs::LnProcessor;

#[derive(Args)]
pub struct ListFundsSubcommand {}

pub async fn list_funds<L>(_sub_command_args: &ListFundsSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let c = ln.get_balance().await.unwrap();

    println!("{:?}", c);

    Ok(())
}
