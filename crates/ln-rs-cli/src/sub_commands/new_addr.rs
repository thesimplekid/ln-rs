use anyhow::Result;
use clap::Args;
use ln_rs::Ln;

#[derive(Args)]
pub struct NewAddrSubcommand {}

pub async fn new_addr(_sub_command_args: &NewAddrSubcommand, ln: Ln) -> Result<()> {
    let c = ln.ln_processor.new_onchain_address().await.unwrap();

    println!("{}", c.to_string());

    Ok(())
}
