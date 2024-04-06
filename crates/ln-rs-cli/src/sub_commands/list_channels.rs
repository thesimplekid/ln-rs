use anyhow::Result;
use clap::Args;
use ln_rs::Ln;

#[derive(Args)]
pub struct ListChannelsSubcommand {}

pub async fn list_channels(_sub_command_args: &ListChannelsSubcommand, ln: Ln) -> Result<()> {
    let response = ln.ln_processor.list_channels().await.unwrap();

    println!("Channels: {:?}", response);

    Ok(())
}
