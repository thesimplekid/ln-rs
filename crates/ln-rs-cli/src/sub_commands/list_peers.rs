use anyhow::Result;
use clap::Args;
use ln_rs::Ln;

#[derive(Args)]
pub struct ListPeersSubcommand {}

pub async fn list_peers(_sub_command_args: &ListPeersSubcommand, ln: Ln) -> Result<()> {
    let response = ln.ln_processor.list_peers().await?;

    for peer in response {
        println!("{:?}", peer);
    }

    Ok(())
}
