use std::str::FromStr;

use anyhow::Result;
use bip39::Mnemonic;
use clap::{Parser, Subcommand};

mod sub_commands;

/// Simple CLI application to interact with ln
#[derive(Parser)]
#[command(name = "ln-rs-cli")]
#[command(author = "thesimplekid <tsk@thesimplekid.com>")]
#[command(version = "0.1")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    NewAddr(sub_commands::new_addr::NewAddrSubcommand),
    ListFunds(sub_commands::list_funds::ListFundsSubcommand),
    GetInvoice(sub_commands::get_invoice::GetInvoiceSubcommand),
    PayInvoice(sub_commands::pay_invoice::PayInvoiceSubcommand),
    CheckInvoiceStatus(sub_commands::check_invoice_status::CheckInvoiceStatusSubcommand),
    OpenChannel(sub_commands::open_channel::OpenChannelSubcommand),
    ListChannel(sub_commands::list_channels::ListChannelsSubcommand),
    CreateInvoice(sub_commands::create_invoice::CreateInvoiceSubcommand),
    PayOnChain(sub_commands::pay_onchain::PayOnChainSubcommand),
    Close(sub_commands::close::CloseSubcommand),
    ConnectPeer(sub_commands::connect_peer::ConnectPeerSubcommand),
    ListPeers(sub_commands::list_peers::ListPeersSubcommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // Parse input
    let args: Cli = Cli::parse();

    let m = Mnemonic::from_str(
        "news image cigar behave twist truly negative globe during scissors model client",
    )
    .unwrap();

    let ln = ln_rs::Greenlight::recover(m, "./client.crt", "./client-key.pem", "testnet", None)
        .await
        .unwrap();

    match &args.command {
        Commands::NewAddr(sub_command_args) => {
            sub_commands::new_addr::new_addr(sub_command_args, ln).await
        }
        Commands::ListFunds(sub_command_args) => {
            sub_commands::list_funds::list_funds(sub_command_args, ln).await
        }
        Commands::GetInvoice(sub_command_args) => {
            sub_commands::get_invoice::get_invoice(sub_command_args, ln).await
        }
        Commands::PayInvoice(sub_command_args) => {
            sub_commands::pay_invoice::pay_invoice(sub_command_args, ln).await
        }
        Commands::CheckInvoiceStatus(sub_command_args) => {
            sub_commands::check_invoice_status::check_invoice_status(sub_command_args, ln).await
        }
        Commands::OpenChannel(sub_command_args) => {
            sub_commands::open_channel::open_channel(sub_command_args, ln).await
        }
        Commands::ListChannel(sub_command_args) => {
            sub_commands::list_channels::list_channels(sub_command_args, ln).await
        }
        Commands::CreateInvoice(sub_command_args) => {
            sub_commands::create_invoice::create_invoice(sub_command_args, ln).await
        }
        Commands::PayOnChain(sub_command_args) => {
            sub_commands::pay_onchain::pay_onchain(sub_command_args, ln).await
        }
        Commands::Close(sub_command_args) => sub_commands::close::close(sub_command_args, ln).await,
        Commands::ConnectPeer(sub_command_args) => {
            sub_commands::connect_peer::connect_peer(sub_command_args, ln).await
        }
        Commands::ListPeers(sub_command_args) => {
            sub_commands::list_peers::list_peers(sub_command_args, ln).await
        }
    }
}
