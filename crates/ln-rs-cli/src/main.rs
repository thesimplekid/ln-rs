use std::io::Error;
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, fs};

use anyhow::{bail, Result};
use bip39::Mnemonic;
use bitcoin::Network;
use clap::{Parser, Subcommand};
use ln_rs::Ln;
use serde::{Deserialize, Serialize};

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
    #[arg(short, long, default_value_t = Network::Bitcoin)]
    network: Network,
    #[arg(short, long, default_value_t = String::from("greenlight"))]
    ln_backend: String,
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum LnBackend {
    #[default]
    Cln,
    Greenlight,
    Ldk,
}

impl FromStr for LnBackend {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cln" => Ok(Self::Cln),
            "greenlight" => Ok(Self::Greenlight),
            "ldk" => Ok(Self::Ldk),
            _ => Err(Error::new(std::io::ErrorKind::Other, "")),
        }
    }
}

impl fmt::Display for LnBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LnBackend::Cln => write!(f, "cln"),
            LnBackend::Greenlight => write!(f, "greenlight"),
            LnBackend::Ldk => write!(f, "ldk"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // Parse input
    let args: Cli = Cli::parse();

    let ln_backend = LnBackend::from_str(&args.ln_backend)?;

    let ln: Ln = match ln_backend {
        LnBackend::Greenlight => {
            let seed_path = "./seed";
            let cert_path = "./client.crt";
            let key_path = "./client-key.pem";

            let greenlight_mnemonic = match fs::metadata(&seed_path) {
                Ok(_) => {
                    let contents = fs::read_to_string(seed_path)?;
                    Mnemonic::from_str(&contents)?
                }
                Err(_e) => bail!("Seed undefined"),
            };

            let greenlight = if let Ok(greenlight) = ln_rs::Greenlight::recover(
                greenlight_mnemonic.clone(),
                cert_path,
                key_path,
                &args.network,
                None,
            )
            .await
            {
                greenlight
            } else {
                let greenlight =
                    ln_rs::Greenlight::new(greenlight_mnemonic, cert_path, key_path, &args.network)
                        .await;

                greenlight?
            };

            Ln {
                ln_processor: Arc::new(greenlight),
            }
        }
        LnBackend::Cln => {
            todo!();
        }
        LnBackend::Ldk => {
            todo!();
        }
    };

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
