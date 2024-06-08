use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;
// use cashu_crab::{Amount, Bolt11Invoice, Sha256};
use cln_rpc::model::requests::{
    CloseRequest, ConnectRequest, FundchannelRequest, InvoiceRequest, KeysendRequest,
    ListfundsRequest, ListinvoicesRequest, ListpeersRequest, NewaddrRequest, PayRequest,
    WaitanyinvoiceRequest, WithdrawRequest,
};
use cln_rpc::model::responses::{
    ListfundsChannels, ListfundsOutputsStatus, ListpeerchannelsChannels,
    ListpeerchannelsChannelsState, ListpeersPeers, PayStatus, WaitanyinvoiceResponse,
};
use cln_rpc::model::{Request, Response};
use cln_rpc::primitives::{Amount as CLN_Amount, AmountOrAll, AmountOrAny, ChannelState};
use futures::{Stream, StreamExt};
use lightning_invoice::Bolt11Invoice;
use ln_rs_models::responses::BalanceResponse;
use ln_rs_models::{requests, responses, Amount, ChannelStatus, InvoiceStatus, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use uuid::Uuid;

use super::{Error, InvoiceInfo, LnProcessor};
use crate::utils::cln_invoice_status_to_status;

#[derive(Clone)]
pub struct Cln {
    rpc_socket: PathBuf,
    cln_client: Arc<Mutex<cln_rpc::ClnRpc>>,
    last_pay_index: Option<u64>,
}

impl Cln {
    pub async fn new(rpc_socket: PathBuf, last_pay_index: Option<u64>) -> Result<Self, Error> {
        let cln_client = cln_rpc::ClnRpc::new(&rpc_socket).await?;
        let cln_client = Arc::new(Mutex::new(cln_client));

        Ok(Self {
            rpc_socket,
            cln_client,
            last_pay_index,
        })
    }
}

#[async_trait]
impl LnProcessor for Cln {
    async fn get_invoice(
        &self,
        amount: Amount,
        hash: Sha256,
        description: &str,
    ) -> Result<InvoiceInfo, Error> {
        let mut cln_client = cln_rpc::ClnRpc::new(&self.rpc_socket).await?;

        let cln_response = cln_client
            .call(cln_rpc::Request::Invoice(InvoiceRequest {
                amount_msat: AmountOrAny::Amount(CLN_Amount::from_sat(amount.into())),
                description: description.to_string(),
                label: Uuid::new_v4().to_string(),
                expiry: None,
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: Some(true),
                exposeprivatechannels: None,
            }))
            .await?;

        match cln_response {
            cln_rpc::Response::Invoice(invoice_response) => {
                let invoice = Bolt11Invoice::from_str(&invoice_response.bolt11)?;
                let payment_hash = Sha256::from_str(&invoice_response.payment_hash.to_string())?;
                let invoice_info = InvoiceInfo::new(
                    payment_hash,
                    hash,
                    invoice,
                    amount,
                    super::InvoiceStatus::Unpaid,
                    "",
                    None,
                );

                Ok(invoice_info)
            }
            _ => panic!("CLN returned wrong response kind"),
        }
    }

    async fn wait_invoice(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = (Bolt11Invoice, Option<u64>)> + Send>>, Error> {
        let last_pay_index = self.last_pay_index;

        let cln_client = cln_rpc::ClnRpc::new(&self.rpc_socket).await?;

        Ok(futures::stream::unfold(
            (cln_client, last_pay_index),
            |(mut cln_client, mut last_pay_idx)| async move {
                // We loop here since some invoices aren't zaps, in which case we wait for the
                // next one and don't yield
                loop {
                    // info!("Waiting for index: {last_pay_idx:?}");
                    let invoice_res = cln_client
                        .call(cln_rpc::Request::WaitAnyInvoice(WaitanyinvoiceRequest {
                            timeout: None,
                            lastpay_index: last_pay_idx,
                        }))
                        .await;

                    let invoice: WaitanyinvoiceResponse = match invoice_res {
                        Ok(invoice) => invoice,
                        Err(e) => {
                            warn!("Error fetching invoice: {e}");
                            // Let's not spam CLN with requests on failure
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            // Retry same request
                            continue;
                        }
                    }
                    .try_into()
                    .expect("Wrong response from CLN");

                    last_pay_idx = invoice.pay_index;

                    let invoice = Bolt11Invoice::from_str(&invoice.bolt11.unwrap()).unwrap();

                    break Some(((invoice, last_pay_idx), (cln_client, last_pay_idx)));
                }
            },
        )
        .boxed())
    }

    async fn check_invoice_status(
        &self,
        payment_hash: &Sha256,
    ) -> Result<super::InvoiceStatus, Error> {
        let mut cln_client = cln_rpc::ClnRpc::new(&self.rpc_socket).await?;

        let cln_response = cln_client
            .call(Request::ListInvoices(ListinvoicesRequest {
                payment_hash: Some(payment_hash.to_string()),
                label: None,
                invstring: None,
                offer_id: None,
                index: None,
                limit: None,
                start: None,
            }))
            .await?;

        let status = match cln_response {
            cln_rpc::Response::ListInvoices(invoice_response) => {
                let i = invoice_response.invoices[0].clone();

                cln_invoice_status_to_status(i.status)
            }
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::Custom(
                    "CLN returned wrong response kind".to_string(),
                ));
            }
        };

        Ok(status)
    }

    async fn pay_invoice(
        &self,
        bolt11: Bolt11Invoice,
        partial_msat: Option<Amount>,
        max_fee: Option<Amount>,
    ) -> Result<responses::PayInvoiceResponse, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(Request::Pay(PayRequest {
                bolt11: bolt11.to_string(),
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: None,
                retry_for: None,
                maxdelay: None,
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                maxfee: max_fee.map(|a| CLN_Amount::from_msat(a.to_msat())),
                description: None,
                partial_msat: partial_msat.map(|a| CLN_Amount::from_msat(a.to_msat())),
            }))
            .await?;

        let response = match cln_response {
            cln_rpc::Response::Pay(pay_response) => {
                let status = match pay_response.status {
                    PayStatus::COMPLETE => InvoiceStatus::Paid,
                    PayStatus::PENDING => InvoiceStatus::InFlight,
                    PayStatus::FAILED => InvoiceStatus::Unpaid,
                };
                responses::PayInvoiceResponse {
                    payment_preimage: Some(hex::encode(pay_response.payment_preimage.to_vec())),
                    payment_hash: Sha256::from_str(&pay_response.payment_hash.to_string())?,
                    status,
                    total_spent: Amount::from_msat(pay_response.amount_sent_msat.msat()),
                }
            }
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(response)
    }

    async fn new_onchain_address(&self) -> Result<Address, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(cln_rpc::Request::NewAddr(NewaddrRequest {
                addresstype: None,
            }))
            .await?;

        let address: Address = match cln_response {
            cln_rpc::Response::NewAddr(addr_res) => Address::from_str(
                &addr_res
                    .bech32
                    .ok_or(Error::Custom("No bech32".to_string()))?,
            )?
            .assume_checked(),
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(address)
    }

    async fn open_channel(
        &self,
        open_channel_request: requests::OpenChannelRequest,
    ) -> Result<String, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(cln_rpc::Request::FundChannel(
                from_open_request_to_fund_request(open_channel_request)?,
            ))
            .await?;

        let channel_id = match cln_response {
            Response::FundChannel(addr_res) => addr_res.channel_id,
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(channel_id.to_string())
    }

    async fn list_channels(&self) -> Result<Vec<responses::ChannelInfo>, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(Request::ListFunds(ListfundsRequest { spent: Some(false) }))
            .await?;

        let channels = match cln_response {
            Response::ListFunds(channels) => channels
                .channels
                .iter()
                .flat_map(from_channel_to_info)
                .filter(|x| x.status.ne(&ChannelStatus::Closed))
                .collect(),
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(channels)
    }

    async fn get_balance(&self) -> Result<responses::BalanceResponse, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(Request::ListFunds(ListfundsRequest { spent: None }))
            .await?;

        let balance = match cln_response {
            cln_rpc::Response::ListFunds(funds_response) => {
                let mut on_chain_total = CLN_Amount::from_msat(0);
                let mut on_chain_spendable = CLN_Amount::from_msat(0);
                let mut ln = CLN_Amount::from_msat(0);

                for output in funds_response.outputs {
                    match output.status {
                        ListfundsOutputsStatus::UNCONFIRMED => {
                            on_chain_total = on_chain_total + output.amount_msat;
                        }
                        ListfundsOutputsStatus::IMMATURE => {
                            on_chain_total = on_chain_total + output.amount_msat;
                        }
                        ListfundsOutputsStatus::CONFIRMED => {
                            on_chain_total = on_chain_total + output.amount_msat;
                            on_chain_spendable = on_chain_spendable + output.amount_msat;
                        }
                        ListfundsOutputsStatus::SPENT => (),
                    }
                }

                for channel in funds_response.channels {
                    ln = ln + channel.our_amount_msat;
                }

                BalanceResponse {
                    on_chain_spendable: Amount::from_msat(on_chain_spendable.msat()),
                    on_chain_total: Amount::from_msat(on_chain_total.msat()),
                    ln: Amount::from_msat(ln.msat()),
                }
            }
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(balance)
    }

    async fn create_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> Result<Bolt11Invoice, Error> {
        let mut cln_client = self.cln_client.lock().await;

        let amount_msat = AmountOrAny::Amount(CLN_Amount::from_msat(amount.to_msat()));
        let cln_response = cln_client
            .call(cln_rpc::Request::Invoice(InvoiceRequest {
                amount_msat,
                description,
                label: Uuid::new_v4().to_string(),
                expiry: Some(3600),
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: None,
                exposeprivatechannels: None,
            }))
            .await?;

        let invoice = match cln_response {
            cln_rpc::Response::Invoice(invoice_res) => {
                Bolt11Invoice::from_str(&invoice_res.bolt11)?
            }
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(invoice)
    }

    async fn pay_on_chain(&self, address: Address, amount: Amount) -> Result<String, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let satoshi = AmountOrAll::Amount(CLN_Amount::from_sat(amount.to_sat()));

        let cln_response = cln_client
            .call(cln_rpc::Request::Withdraw(WithdrawRequest {
                destination: address.to_string(),
                satoshi,
                feerate: None,
                minconf: None,
                utxos: None,
            }))
            .await?;

        let txid = match cln_response {
            cln_rpc::Response::Withdraw(withdraw_response) => withdraw_response.txid,
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(txid)
    }

    async fn close(&self, channel_id: String, peer_id: Option<PublicKey>) -> Result<(), Error> {
        let mut cln_client = self.cln_client.lock().await;

        let destination = peer_id.map(|x| x.to_string());
        let cln_response = cln_client
            .call(cln_rpc::Request::Close(CloseRequest {
                id: channel_id,
                unilateraltimeout: None,
                destination,
                fee_negotiation_step: None,
                wrong_funding: None,
                force_lease_closed: None,
                feerange: None,
            }))
            .await?;

        let _txid = match cln_response {
            cln_rpc::Response::Close(close_res) => close_res.txid,
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(())
    }

    async fn pay_keysend(&self, destination: PublicKey, amount: Amount) -> Result<String, Error> {
        let destination = cln_rpc::primitives::PublicKey::from_slice(&destination.serialize())?;

        let amount_msat = CLN_Amount::from_msat(amount.to_msat());

        let mut cln_client = self.cln_client.lock().await;

        let cln_response = cln_client
            .call(Request::KeySend(KeysendRequest {
                destination,
                amount_msat,
                label: None,
                maxfeepercent: None,
                retry_for: None,
                maxdelay: None,
                exemptfee: None,
                routehints: None,
                extratlvs: None,
            }))
            .await?;

        let payment_hash = match cln_response {
            Response::KeySend(keysend_res) => keysend_res.payment_hash,
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(payment_hash.to_string())
    }

    async fn connect_peer(
        &self,
        public_key: PublicKey,
        host: String,
        port: u16,
    ) -> Result<responses::PeerInfo, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(Request::Connect(ConnectRequest {
                id: public_key.to_string(),
                host: Some(host.clone()),
                port: Some(port),
            }))
            .await?;

        let _peers = match cln_response {
            cln_rpc::Response::Connect(connect_response) => connect_response.id,
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };
        debug!("Peer Response: {:?}", _peers);

        let peer_info = responses::PeerInfo {
            peer_pubkey: public_key,
            host,
            port,
            connected: true,
        };

        Ok(peer_info)
    }

    async fn list_peers(&self) -> Result<Vec<responses::PeerInfo>, Error> {
        let mut cln_client = self.cln_client.lock().await;
        let cln_response = cln_client
            .call(Request::ListPeers(ListpeersRequest {
                id: None,
                level: None,
            }))
            .await?;

        let peers = match cln_response {
            Response::ListPeers(peers) => peers.peers.iter().flat_map(from_peer_to_info).collect(),
            _ => {
                warn!("CLN returned wrong response kind");
                return Err(Error::WrongClnResponse);
            }
        };

        Ok(peers)
    }
}

pub fn fee_reserve(invoice_amount: Amount) -> Amount {
    let fee_reserse = (u64::from(invoice_amount) as f64 * 0.01) as u64;

    Amount::from(fee_reserse)
}

fn from_open_request_to_fund_request(
    open_channel_request: requests::OpenChannelRequest,
) -> Result<FundchannelRequest, Error> {
    let requests::OpenChannelRequest {
        public_key,
        host: _,
        port: _,
        amount,
        push_amount,
    } = open_channel_request;

    let push_amount = push_amount.map(|a| cln_rpc::primitives::Amount::from_sat(a.to_sat()));

    let amount = AmountOrAll::Amount(cln_rpc::primitives::Amount::from_sat(amount.to_sat()));

    let public_key = cln_rpc::primitives::PublicKey::from_slice(&public_key.serialize())?;

    Ok(FundchannelRequest {
        id: public_key,
        amount,
        channel_type: None,
        // FIXME:
        feerate: Some(cln_rpc::primitives::Feerate::PerKb(10)),
        announce: None,
        minconf: None,
        push_msat: push_amount,
        close_to: None,
        request_amt: None,
        compact_lease: None,
        utxos: None,
        mindepth: None,
        reserve: None,
    })
}

fn from_peer_to_info(peer: &ListpeersPeers) -> Result<responses::PeerInfo, Error> {
    let peer_pubkey = PublicKey::from_str(&peer.id.to_string())?;

    let connected = peer.connected;

    debug!("{:?}", peer);

    let remote_addr: Vec<String> = peer
        .clone()
        .netaddr
        .ok_or(Error::Custom("No net address".to_string()))?[0]
        .split(':')
        .map(|s| s.to_string())
        .collect();

    let host = remote_addr[0].to_string();
    let port = remote_addr[1].parse::<u16>()?;

    Ok(responses::PeerInfo {
        peer_pubkey,
        host,
        port,
        connected,
    })
}

fn from_channel_to_info(channel: &ListfundsChannels) -> Result<responses::ChannelInfo, Error> {
    let peer_pubkey = PublicKey::from_slice(&channel.peer_id.serialize())?;
    let channel_id = channel
        .channel_id
        .ok_or(Error::Custom("No Channel Id".to_string()))?
        .to_string();
    let balance = channel.our_amount_msat;
    let value = channel.amount_msat;
    let is_usable = channel.connected;

    // FIXME:
    let status = match channel.state {
        ChannelState::OPENINGD => ChannelStatus::PendingOpen,
        ChannelState::CHANNELD_NORMAL => ChannelStatus::Active,
        ChannelState::CHANNELD_SHUTTING_DOWN => ChannelStatus::PendingClose,
        ChannelState::CLOSINGD_COMPLETE => ChannelStatus::Closed,
        ChannelState::ONCHAIN => ChannelStatus::Closed,
        _ => ChannelStatus::Inactive,
    };

    Ok(responses::ChannelInfo {
        peer_pubkey,
        channel_id,
        balance: Amount::from_msat(balance.msat()),
        value: Amount::from_msat(value.msat()),
        is_usable,
        status,
    })
}

fn _from_list_channels_to_info(
    list_channel: ListpeerchannelsChannels,
) -> Result<responses::ChannelInfo, Error> {
    debug!("{:?}", list_channel.funding);
    let remote_balance = list_channel.funding.as_ref().map_or(Amount::ZERO, |a| {
        Amount::from_msat(a.remote_funds_msat.msat())
    });
    let local_balance = list_channel.funding.map_or(Amount::ZERO, |a| {
        Amount::from_msat(a.local_funds_msat.msat())
    });

    // FIXME:
    let is_usable = false;

    /*        list_channel
        .state
        .map(|s| matches!(s, ListpeerchannelsChannelsState::CHANNELD_NORMAL))
        .unwrap_or(false);
    */

    let status = match list_channel.state {
        ListpeerchannelsChannelsState::CHANNELD_NORMAL => ChannelStatus::Active,
        ListpeerchannelsChannelsState::OPENINGD => ChannelStatus::PendingOpen,
        _ => ChannelStatus::PendingClose,
    };

    Ok(responses::ChannelInfo {
        peer_pubkey: PublicKey::from_slice(&list_channel.peer_id.serialize())?,
        channel_id: list_channel
            .channel_id
            .ok_or(Error::Custom("No Channel Id".to_string()))?
            .to_string(),
        balance: local_balance,
        value: local_balance + remote_balance,
        is_usable,
        status,
    })
}
