use anyhow::Result;
use clap::Args;
use ln_rs::LnProcessor;

#[derive(Args)]
pub struct ListPeersSubcommand {}

pub async fn list_peers<L>(_sub_command_args: &ListPeersSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let response = ln.list_peers().await.unwrap();

    for peer in response {
        println!("{:?}", peer);
    }

    Ok(())
}
