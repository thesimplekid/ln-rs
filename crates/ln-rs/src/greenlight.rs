use std::fs;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network};
use futures::{Stream, StreamExt};
use gl_client::credentials::{self, Device};
use gl_client::node::ClnClient;
use gl_client::pb::cln;
use gl_client::pb::cln::listfunds_outputs::ListfundsOutputsStatus;
use gl_client::scheduler::Scheduler;
use gl_client::signer::model::cln::amount_or_any::Value as SignerValue;
use gl_client::signer::model::cln::{
    Amount as SignerAmount, GetinfoRequest, ListpeerchannelsRequest,
};
use gl_client::signer::model::greenlight::cln::InvoiceResponse;
use gl_client::signer::Signer;
use ln_rs_models::responses::PayInvoiceResponse;
use ln_rs_models::{requests, responses, Amount, ChannelStatus, InvoiceStatus, Sha256};
use tokio::sync::Mutex;
use tracing::debug;
use tracing::log::warn;
use uuid::Uuid;

use super::{Error, InvoiceInfo, LnProcessor};
use crate::utils::gln_invoice_status_to_status;
use crate::Bolt11Invoice;

#[derive(Clone)]
pub struct Greenlight {
    signer: Signer,
    signer_tx: Option<tokio::sync::mpsc::Sender<()>>,
    node: Arc<Mutex<ClnClient>>,
    last_pay_index: Option<u64>,
}

impl Greenlight {
    pub async fn new(
        mnemonic: Mnemonic,
        device_cert_path: &str,
        device_key_path: &str,
        network: &Network,
    ) -> Result<Self, Error> {
        let network: gl_client::bitcoin::Network = match network {
            Network::Bitcoin => gl_client::bitcoin::Network::Bitcoin,
            Network::Testnet => gl_client::bitcoin::Network::Testnet,
            Network::Regtest => gl_client::bitcoin::Network::Regtest,
            _ => return Err(Error::Custom("Unsupported network".to_string())),
        };

        let seed = mnemonic.to_seed("");

        let secret = seed[0..32].to_vec();

        let (device_cert, device_key) = if let (Ok(_), Ok(_)) = (
            fs::metadata(device_cert_path),
            fs::metadata(device_key_path),
        ) {
            (
                fs::read_to_string(device_cert_path)?,
                fs::read_to_string(device_key_path)?,
            )
        } else {
            return Err(Error::Custom("Device cert and/or key unknown".to_string()));
        };

        let creds = credentials::Nobody {
            cert: device_cert.into_bytes(),
            key: device_key.into_bytes(),
            ..Default::default()
        };

        let signer = Signer::new(secret.clone(), network, creds.clone()).unwrap();

        let scheduler_unauth = Scheduler::new(signer.node_id(), network, creds.clone())
            .await
            .unwrap();

        let auth_response = scheduler_unauth.register(&signer, None).await?;

        let creds = Device::from_bytes(auth_response.creds);

        let scheduler_auth = scheduler_unauth.authenticate(creds.clone()).await.unwrap();

        //tracing::info!("cert {:?}", device_cert);
        //tracing::info!("key {:?}", device_key);

        let signer = Signer::new(secret, network, creds.clone()).unwrap();

        let mut node: gl_client::node::ClnClient = scheduler_auth.node().await?;
        let info = node
            .getinfo(GetinfoRequest::default())
            .await
            .map_err(|x| Error::TonicError(x.to_string()))?;
        tracing::debug!("Info {:?}", info);

        let node = Arc::new(Mutex::new(node));
        tracing::warn!("Node up");
        Ok(Self {
            signer,
            signer_tx: None,
            node,
            last_pay_index: None,
        })
    }

    pub fn start_signer(&mut self) -> Result<(), Error> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let signer_clone = self.signer.clone();

        self.signer_tx = Some(tx);
        tokio::spawn(async move {
            if let Err(err) = signer_clone.run_forever(rx).await {
                debug!("{:?}", err);
            }
        });

        Ok(())
    }

    pub async fn recover(
        mnemonic: Mnemonic,
        device_cert_path: &str,
        device_key_path: &str,
        network: &Network,
        last_pay_index: Option<u64>,
    ) -> Result<Self, Error> {
        let network: gl_client::bitcoin::Network = match network {
            Network::Bitcoin => gl_client::bitcoin::Network::Bitcoin,
            Network::Testnet => gl_client::bitcoin::Network::Testnet,
            Network::Regtest => gl_client::bitcoin::Network::Regtest,
            _ => return Err(Error::Custom("Unsupported network".to_string())),
        };

        let seed = mnemonic.to_seed("");
        let secret = seed[0..32].to_vec();

        let (device_cert, device_key) = if let (Ok(_), Ok(_)) = (
            fs::metadata(device_cert_path),
            fs::metadata(device_key_path),
        ) {
            (
                fs::read_to_string(device_cert_path)?,
                fs::read_to_string(device_key_path)?,
            )
        } else {
            return Err(Error::Custom("Device cert and/or key unknown".to_string()));
        };

        let creds = credentials::Nobody {
            cert: device_cert.into_bytes(),
            key: device_key.into_bytes(),
            ..Default::default()
        };

        let signer = Signer::new(secret.clone(), network, creds.clone())?;

        let scheduler_unauth = Scheduler::new(signer.node_id(), network, creds.clone())
            .await
            .unwrap();

        let auth_response = scheduler_unauth.recover(&signer).await?;

        let creds = Device::from_bytes(auth_response.creds);

        let scheduler_auth = scheduler_unauth.authenticate(creds.clone()).await.unwrap();

        let mut node: gl_client::node::ClnClient = scheduler_auth.node().await?;
        let info = node
            .getinfo(GetinfoRequest::default())
            .await
            .map_err(|x| Error::TonicError(x.to_string()))?;

        tracing::warn!("Info {:?}", info);

        let node = Arc::new(Mutex::new(node));
        tracing::warn!("Node up");

        Ok(Self {
            signer,
            signer_tx: None,
            node,
            last_pay_index,
        })
    }
}

#[async_trait]
impl LnProcessor for Greenlight {
    async fn get_invoice(
        &self,
        amount: Amount,
        hash: Sha256,
        description: &str,
    ) -> Result<InvoiceInfo, Error> {
        let mut cln_client = self.node.lock().await;

        let cln_response = cln_client
            .invoice(cln::InvoiceRequest {
                amount_msat: Some(cln::AmountOrAny {
                    value: Some(SignerValue::Amount(cln::Amount {
                        msat: u64::from(amount) * 1000,
                    })),
                }),
                description: description.to_string(),
                label: Uuid::new_v4().to_string(),
                expiry: None,
                fallbacks: vec![],
                preimage: None,
                cltv: None,
                deschashonly: Some(true),
            })
            .await
            .map_err(|_| Error::Custom("Tonic Error".to_string()))?;

        let InvoiceResponse {
            bolt11,
            payment_hash,
            ..
        } = cln_response.into_inner();

        let invoice = {
            let invoice = Bolt11Invoice::from_str(&bolt11)?;
            let payment_hash = Sha256::from_str(&String::from_utf8(payment_hash)?)?;
            InvoiceInfo::new(
                payment_hash,
                hash,
                invoice,
                amount,
                super::InvoiceStatus::Unpaid,
                "",
                None,
            )
        };

        Ok(invoice)
    }

    async fn wait_invoice(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = (Bolt11Invoice, Option<u64>)> + Send>>, Error> {
        let last_pay_index = self.last_pay_index;

        let cln_client = self.node.lock().await.clone();

        Ok(futures::stream::unfold(
            (cln_client, last_pay_index),
            |(mut cln_client, mut last_pay_idx)| async move {
                // We loop here since some invoices aren't zaps, in which case we wait for the
                // next one and don't yield
                loop {
                    let invoice_res = cln_client
                        .wait_any_invoice(cln::WaitanyinvoiceRequest {
                            lastpay_index: last_pay_idx,
                            timeout: None,
                        })
                        .await;

                    let invoice: cln::WaitanyinvoiceResponse = invoice_res.unwrap().into_inner();

                    last_pay_idx = invoice.pay_index;

                    let invoice = Bolt11Invoice::from_str(&invoice.bolt11.unwrap()).unwrap();

                    break Some(((invoice, last_pay_idx), (cln_client, last_pay_idx)));
                }
            },
        )
        .boxed())
    }

    async fn check_invoice_status(&self, payment_hash: &Sha256) -> Result<InvoiceStatus, Error> {
        let mut cln_client = self.node.lock().await;

        let cln_response = cln_client
            .list_invoices(cln::ListinvoicesRequest {
                payment_hash: Some(payment_hash.to_string().as_bytes().to_vec()),
                ..Default::default()
            })
            .await
            .map_err(|_| Error::Custom("Tonic Error".to_string()))?;

        let cln::ListinvoicesResponse { invoices, .. } = cln_response.into_inner();

        let status = {
            debug!("{:?}", invoices);
            let i = invoices[0].clone();

            gln_invoice_status_to_status(i.status())
        };

        Ok(status)
    }

    async fn pay_invoice(
        &self,
        invoice: Bolt11Invoice,
        max_fee: Option<Amount>,
    ) -> Result<PayInvoiceResponse, Error> {
        let mut cln_client = self.node.lock().await;

        let maxfee = max_fee.map(|amount| cln::Amount {
            msat: amount.to_msat(),
        });

        let cln_response = cln_client
            .pay(cln::PayRequest {
                bolt11: invoice.to_string(),
                maxfee,
                ..Default::default()
            })
            .await
            .map_err(|_| Error::Custom("Tonic Error".to_string()))?;

        let cln::PayResponse {
            payment_preimage,
            amount_sent_msat,
            payment_hash,
            ..
        } = cln_response.into_inner();
        let amount_sent_msat = amount_sent_msat.map(|x| x.msat).unwrap_or_default();
        let _invoice = (
            serde_json::to_string(&payment_preimage)?,
            Amount::from_msat(amount_sent_msat),
        );

        let response = PayInvoiceResponse {
            payment_hash: Sha256::from_str(&String::from_utf8(payment_hash)?)?,
            payment_preimage: Some(String::from_utf8(payment_preimage)?),
            status: InvoiceStatus::Paid,
            total_spent: Amount::from_msat(amount_sent_msat),
        };

        Ok(response)
    }

    async fn new_onchain_address(&self) -> Result<Address, Error> {
        let mut node = self.node.lock().await;

        let new_addr = node
            .new_addr(cln::NewaddrRequest { addresstype: None })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?;

        let address = match new_addr.into_inner().bech32 {
            Some(addr) => addr,
            None => return Err(Error::Custom("Could not get address".to_string())),
        };

        let address = Address::from_str(&address)?.assume_checked();

        Ok(address)
    }

    async fn open_channel(
        &self,
        open_channel_request: requests::OpenChannelRequest,
    ) -> Result<String, Error> {
        let mut node = self.node.lock().await;

        let requests::OpenChannelRequest {
            public_key,
            host: _,
            port: _,
            amount,
            push_amount,
        } = open_channel_request;

        let amount = cln::AmountOrAll {
            value: Some(cln::amount_or_all::Value::Amount(SignerAmount {
                msat: amount.to_msat(),
            })),
        };

        let push_msat = push_amount.map(|pa| SignerAmount { msat: pa.to_msat() });

        let request = cln::FundchannelRequest {
            id: public_key.serialize().to_vec(),
            amount: Some(amount),
            push_msat,
            ..Default::default()
        };

        let response = node
            .fund_channel(request)
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?;

        let txid = response.into_inner().txid;

        Ok(String::from_utf8(txid)?)
    }

    async fn list_channels(&self) -> Result<Vec<responses::ChannelInfo>, Error> {
        let mut node = self.node.lock().await;

        let channels_response = node
            .list_peer_channels(ListpeerchannelsRequest { id: None })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        warn!("{:?}", channels_response);

        let channels = channels_response
            .channels
            .into_iter()
            .flat_map(from_list_channels_to_info)
            .collect();

        Ok(channels)
    }

    async fn get_balance(&self) -> Result<responses::BalanceResponse, Error> {
        let mut node = self.node.lock().await;

        let response = node
            .list_funds(cln::ListfundsRequest { spent: None })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        let mut on_chain_total = Amount::default();

        let mut on_chain_spendable = Amount::ZERO;
        let mut ln = Amount::ZERO;

        for output in response.outputs {
            match &output.status() {
                ListfundsOutputsStatus::Unconfirmed => {
                    on_chain_total += Amount::from_msat(
                        output.amount_msat.unwrap_or(cln::Amount::default()).msat,
                    );
                }
                ListfundsOutputsStatus::Immature => {
                    on_chain_total += Amount::from_msat(
                        output.amount_msat.unwrap_or(cln::Amount::default()).msat,
                    );
                }
                ListfundsOutputsStatus::Confirmed => {
                    on_chain_total += Amount::from_msat(
                        output
                            .amount_msat
                            .clone()
                            .unwrap_or(cln::Amount::default())
                            .msat,
                    );
                    on_chain_spendable += Amount::from_msat(
                        output.amount_msat.unwrap_or(cln::Amount::default()).msat,
                    );
                }
                ListfundsOutputsStatus::Spent => (),
            }
        }

        for channel in response.channels {
            ln += Amount::from_msat(
                channel
                    .our_amount_msat
                    .unwrap_or(cln::Amount::default())
                    .msat,
            );
        }

        Ok(responses::BalanceResponse {
            on_chain_spendable,
            on_chain_total,
            ln,
        })
    }

    async fn create_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> Result<Bolt11Invoice, Error> {
        let mut node = self.node.lock().await;

        let amount_msat = cln::AmountOrAny {
            value: Some(cln::amount_or_any::Value::Amount(SignerAmount {
                msat: amount.to_msat(),
            })),
        };

        let response = node
            .invoice(cln::InvoiceRequest {
                amount_msat: Some(amount_msat),
                description,
                label: Uuid::new_v4().to_string(),
                expiry: Some(3600),
                fallbacks: vec![],
                preimage: None,
                cltv: None,
                deschashonly: None,
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();
        let bolt11 = response.bolt11;

        Ok(Bolt11Invoice::from_str(&bolt11)?)
    }

    async fn pay_on_chain(&self, address: Address, amount: Amount) -> Result<String, Error> {
        let mut node = self.node.lock().await;

        let satoshi = Some(cln::AmountOrAll {
            value: Some(cln::amount_or_all::Value::Amount(cln::Amount {
                msat: amount.to_msat(),
            })),
        });

        let response = node
            .withdraw(cln::WithdrawRequest {
                destination: address.to_string(),
                satoshi,
                ..Default::default()
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        Ok(String::from_utf8(response.txid)?)
    }

    async fn close(&self, channel_id: String, peer_id: Option<PublicKey>) -> Result<(), Error> {
        let mut node = self.node.lock().await;

        let destination = peer_id.map(|x| x.to_string());
        let _response = node
            .close(cln::CloseRequest {
                id: channel_id,
                destination,
                ..Default::default()
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?;
        Ok(())
    }

    async fn pay_keysend(&self, destination: PublicKey, amount: Amount) -> Result<String, Error> {
        let mut node = self.node.lock().await;
        let amount_msat = SignerAmount {
            msat: amount.to_msat(),
        };
        let response = node
            .key_send(cln::KeysendRequest {
                destination: destination.serialize().to_vec(),
                amount_msat: Some(amount_msat),
                ..Default::default()
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        Ok(String::from_utf8(response.payment_hash)?)
    }

    async fn connect_peer(
        &self,
        public_key: PublicKey,
        host: String,
        port: u16,
    ) -> Result<responses::PeerInfo, Error> {
        let mut node = self.node.lock().await;

        let _response = node
            .connect_peer(cln::ConnectRequest {
                id: public_key.to_string(),
                host: Some(host.clone()),
                port: Some(port.into()),
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        let peer_info = responses::PeerInfo {
            peer_pubkey: public_key,
            host,
            port,
            connected: true,
        };

        Ok(peer_info)
    }

    async fn list_peers(&self) -> Result<Vec<responses::PeerInfo>, Error> {
        let mut node = self.node.lock().await;

        let response = node
            .list_peers(cln::ListpeersRequest {
                ..Default::default()
            })
            .await
            .map_err(|err| Error::TonicError(err.to_string()))?
            .into_inner();

        let peers = response.peers.iter().flat_map(from_peer_to_info).collect();

        Ok(peers)
    }
}

fn from_peer_to_info(peer: &cln::ListpeersPeers) -> Result<responses::PeerInfo, Error> {
    let peer_pubkey = PublicKey::from_slice(&peer.id)?;

    let connected = peer.connected;

    let remote_addr: Vec<String> = peer.clone().netaddr[0]
        .split(':')
        .map(|s| s.to_string())
        .collect();

    let host = remote_addr[0].to_string();
    let port = remote_addr[1].parse::<u16>().unwrap_or_default();

    Ok(responses::PeerInfo {
        peer_pubkey,
        host,
        port,
        connected,
    })
}

fn from_list_channels_to_info(
    list_channel: cln::ListpeerchannelsChannels,
) -> Result<responses::ChannelInfo, Error> {
    let remote_balance = list_channel.funding.as_ref().map_or(Amount::ZERO, |a| {
        Amount::from_msat(
            a.remote_funds_msat
                .clone()
                .unwrap_or(SignerAmount { msat: 0 })
                .msat,
        )
    });

    let local_balance = list_channel.clone().funding.map_or(Amount::ZERO, |a| {
        Amount::from_msat(a.local_funds_msat.unwrap_or(SignerAmount { msat: 0 }).msat)
    });

    let is_usable = list_channel
        .state
        // FIXME: Not sure what number is active
        .map(|s| matches!(s, 0))
        .unwrap_or(false);

    let status = if list_channel.state.unwrap_or(0) > 1 {
        ChannelStatus::Active
    } else {
        ChannelStatus::Inactive
    };

    Ok(responses::ChannelInfo {
        peer_pubkey: PublicKey::from_slice(
            &list_channel
                .clone()
                .peer_id
                .ok_or(Error::Custom("No peer id".to_string()))?,
        )?,
        channel_id: hex::encode(list_channel.clone().channel_id()),
        balance: local_balance,
        value: local_balance + remote_balance,
        is_usable,
        status,
    })
}
