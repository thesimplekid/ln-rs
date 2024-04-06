use anyhow::Result;
use clap::Args;
use ln_rs::LnProcessor;

#[derive(Args)]
pub struct NewAddrSubcommand {}

pub async fn new_addr<L>(_sub_command_args: &NewAddrSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let c = ln.new_onchain_address().await.unwrap();

    println!("{}", c.to_string());

    Ok(())
}
