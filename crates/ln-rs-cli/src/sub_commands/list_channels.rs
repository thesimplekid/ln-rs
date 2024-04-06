use anyhow::Result;
use clap::Args;
use ln_rs::LnProcessor;

#[derive(Args)]
pub struct ListChannelsSubcommand {}

pub async fn list_channels<L>(_sub_command_args: &ListChannelsSubcommand, ln: L) -> Result<()>
where
    L: LnProcessor,
{
    let response = ln.list_channels().await.unwrap();

    println!("Channels: {:?}", response);

    Ok(())
}
