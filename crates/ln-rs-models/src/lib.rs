use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

mod amount;

pub use amount::Amount;
pub use bitcoin::hashes::sha256::Hash as Sha256;

pub mod requests {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Serialize};

    use super::Amount;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreateInvoiceParams {
        pub msat: u64,
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeysendRequest {
        /// Amount in sats
        pub amount: u64,
        pub pubkey: PublicKey,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OpenChannelRequest {
        pub public_key: PublicKey,
        pub host: String,
        pub port: u16,
        pub amount: Amount,
        pub push_amount: Option<Amount>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectPeerRequest {
        pub public_key: PublicKey,
        pub host: String,
        pub port: u16,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PayOnChainRequest {
        pub sat: u64,
        pub address: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CloseChannel {
        pub channel_id: String,
        pub peer_id: Option<PublicKey>,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelStatus {
    Active,
    Inactive,
    PendingClose,
    PendingOpen,
    Closed,
}

impl ToString for ChannelStatus {
    fn to_string(&self) -> String {
        match self {
            ChannelStatus::Active => "Active".to_string(),
            ChannelStatus::Inactive => "Inactive".to_string(),
            ChannelStatus::PendingClose => "PendingClose".to_string(),
            ChannelStatus::PendingOpen => "PendingOpen".to_string(),
            ChannelStatus::Closed => "Closed".to_string(),
        }
    }
}

pub mod responses {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Serialize};

    use super::{Amount, InvoiceStatus, Sha256};
    use crate::ChannelStatus;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PayInvoiceResponse {
        pub payment_hash: Sha256,
        pub payment_preimage: Option<String>,
        pub status: InvoiceStatus,
        pub total_spent: Amount,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FundingAddressResponse {
        pub address: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct BalanceResponse {
        pub on_chain_spendable: Amount,
        pub on_chain_total: Amount,
        pub ln: Amount,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChannelInfo {
        pub peer_pubkey: PublicKey,
        pub channel_id: String,
        pub balance: Amount,
        pub value: Amount,
        pub is_usable: bool,
        pub status: ChannelStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct PeerInfo {
        pub peer_pubkey: PublicKey,
        pub host: String,
        pub port: u16,
        pub connected: bool,
    }

    /*
    impl From<ChannelDetails> for ChannelInfo {
        fn from(channel_details: ChannelDetails) -> Self {
            Self {
                peer_pubkey: channel_details.counterparty_node_id,
                balance: Amount::from_msat(channel_details.balance_msat),
                value: Amount::from_sat(channel_details.channel_value_sats),
                is_usable: channel_details.is_usable,
            }
        }
    }
    */

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LoginResponse {
        pub status: String,
        pub token: String,
    }

    impl LoginResponse {
        pub fn as_json(&self) -> anyhow::Result<String> {
            Ok(serde_json::to_string(self)?)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt11 {
    pub bolt11: Bolt11Invoice,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
}
/// Possible states of an invoice
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum InvoiceStatus {
    Unpaid,
    Paid,
    Expired,
    InFlight,
}

impl ToString for InvoiceStatus {
    fn to_string(&self) -> String {
        match self {
            InvoiceStatus::Paid => "Paid".to_string(),
            InvoiceStatus::Unpaid => "Unpaid".to_string(),
            InvoiceStatus::Expired => "Expired".to_string(),
            InvoiceStatus::InFlight => "InFlight".to_string(),
        }
    }
}
