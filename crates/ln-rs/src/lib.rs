use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{secp256k1::PublicKey, Address};
// use cashu_crab::{lightning_invoice::Bolt11Invoice, Amount, Sha256};
use futures::Stream;
use ln_rs_models::{requests, responses};
use serde::{Deserialize, Serialize};

#[cfg(feature = "cln")]
pub use cln::Cln;
pub use error::Error;
#[cfg(feature = "greenlight")]
pub use greenlight::Greenlight;
#[cfg(feature = "ldk")]
pub use ldk::Ldk;
pub use lightning_invoice;
pub use lightning_invoice::Bolt11Invoice;
pub use ln_rs_models::{Amount, InvoiceStatus, Sha256};

#[cfg(feature = "cln")]
pub mod cln;
pub mod error;
#[cfg(feature = "greenlight")]
pub mod greenlight;
pub mod jwt_auth;
#[cfg(feature = "ldk")]
pub mod ldk;
pub mod lnurl;
pub mod node_manager;
pub mod utils;

#[derive(Clone)]
pub struct Ln {
    pub ln_processor: Arc<dyn LnProcessor>,
}

/// Possible states of an invoice
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum InvoiceTokenStatus {
    Issued,
    NotIssued,
}

/// Invoice information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceInfo {
    /// Payment hash of LN Invoice
    pub payment_hash: Sha256,
    /// random hash generated by the mint to internally look up the invoice state
    pub hash: Sha256,
    pub invoice: Bolt11Invoice,
    pub amount: Amount,
    pub status: InvoiceStatus,
    pub token_status: InvoiceTokenStatus,
    pub memo: String,
    pub confirmed_at: Option<u64>,
}

impl InvoiceInfo {
    pub fn new(
        payment_hash: Sha256,
        hash: Sha256,
        invoice: Bolt11Invoice,
        amount: Amount,
        status: InvoiceStatus,
        memo: &str,
        confirmed_at: Option<u64>,
    ) -> Self {
        Self {
            payment_hash,
            hash,
            invoice,
            amount,
            status,
            token_status: InvoiceTokenStatus::NotIssued,
            memo: memo.to_string(),
            confirmed_at,
        }
    }

    pub fn as_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
}

#[async_trait]
pub trait LnProcessor: Send + Sync {
    async fn get_invoice(
        &self,
        amount: Amount,
        hash: Sha256,
        description: &str,
    ) -> Result<InvoiceInfo, Error>;

    async fn wait_invoice(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = (Bolt11Invoice, Option<u64>)> + Send>>, Error>;

    async fn pay_invoice(
        &self,
        bolt11: Bolt11Invoice,
        max_fee: Option<Amount>,
    ) -> Result<responses::PayInvoiceResponse, Error>;

    async fn check_invoice_status(&self, payment_hash: &Sha256) -> Result<InvoiceStatus, Error>;

    async fn new_onchain_address(&self) -> Result<Address, Error>;

    async fn open_channel(
        &self,
        open_channel_request: requests::OpenChannelRequest,
    ) -> Result<String, Error>;

    async fn list_channels(&self) -> Result<Vec<responses::ChannelInfo>, Error>;

    async fn get_balance(&self) -> Result<responses::BalanceResponse, Error>;

    async fn create_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> Result<Bolt11Invoice, Error>;

    async fn pay_on_chain(&self, address: Address, amount: Amount) -> Result<String, Error>;

    async fn close(&self, channel_id: String, peer_id: Option<PublicKey>) -> Result<(), Error>;

    async fn pay_keysend(&self, destination: PublicKey, amount: Amount) -> Result<String, Error>;

    async fn connect_peer(
        &self,
        public_key: PublicKey,
        host: String,
        port: u16,
    ) -> Result<responses::PeerInfo, Error>;

    async fn list_peers(&self) -> Result<Vec<responses::PeerInfo>, Error>;
}
