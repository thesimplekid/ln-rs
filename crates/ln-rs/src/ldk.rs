use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;
use bitcoin_hashes::Hash;
use futures::Stream;
use ldk_node::bitcoin::Network;
use ldk_node::io::SqliteStore;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::{Builder, ChannelDetails, ChannelId, Config, Event, NetAddress, Node, PeerDetails};
use ln_rs_models::responses::ChannelInfo;
use ln_rs_models::{requests, responses, Amount, Bolt11, ChannelStatus, InvoiceStatus, Sha256};
use tracing::debug;

use super::{Error, InvoiceInfo, LnNodeManager, LnProcessor};
use crate::utils::ldk_payment_status;

const SECS_IN_DAY: u32 = 86400;

#[derive(Clone)]
pub struct Ldk {
    pub node: Arc<Node<SqliteStore>>,
}

impl Ldk {
    pub async fn new() -> anyhow::Result<Self> {
        let config = Config {
            log_level: ldk_node::LogLevel::Info,
            ..Default::default()
        };
        let mut builder = Builder::from_config(config);

        // TODO: set network and handle seed better
        builder.set_entropy_seed_path("./myseed".to_string());
        builder.set_network(Network::Signet);
        builder.set_esplora_server("https://mutinynet.com/api".to_string());
        builder.set_gossip_source_rgs("https://rgs.mutinynet.com/snapshot/".to_string());
        /*
        builder.set_esplora_server("https://blockstream.info/testnet/api".to_string());
        builder.set_gossip_source_rgs(
            "https://rapidsync.lightningdevkit.org/testnet/snapshot".to_string(),
        );
        */

        let node = Arc::new(builder.build()?);

        node.start()?;

        Ok(Self { node })
    }
}

#[async_trait]
impl LnProcessor for Ldk {
    async fn get_invoice(
        &self,
        amount: Amount,
        hash: Sha256,
        description: &str,
    ) -> Result<InvoiceInfo, Error> {
        let invoice = self
            .node
            .receive_payment(amount.to_msat(), description, SECS_IN_DAY)?;

        let invoice = Bolt11Invoice::from_str(&invoice.to_string())?;

        let inoice_info = InvoiceInfo::new(
            Sha256::from_str(&invoice.payment_hash().to_owned().to_string())?,
            hash,
            invoice,
            amount,
            InvoiceStatus::Unpaid,
            "",
            None,
        );
        Ok(inoice_info)
    }

    // TODO: needs to be a real stream
    async fn wait_invoice(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = (Bolt11Invoice, Option<u64>)> + Send>>, Error> {
        while let Some(event) = self.node.next_event() {
            match event {
                Event::PaymentReceived {
                    payment_hash,
                    amount_msat: _,
                } => {
                    let _payment_hash =
                        Sha256::from_str(&String::from_utf8(payment_hash.0.to_vec())?)?;

                    self.node.event_handled();
                }
                _ => {
                    debug!("{:?}", event);
                    // TODO: Do something with this
                    self.node.event_handled();
                }
            }
        }
        todo!()
    }

    async fn check_invoice_status(&self, payment_hash: &Sha256) -> Result<InvoiceStatus, Error> {
        let payment_hash = ldk_node::lightning::ln::PaymentHash(payment_hash.to_byte_array());

        let payment = self
            .node
            .list_payments_with_filter(|p| p.hash == payment_hash);

        let status = ldk_payment_status(payment[0].status);

        Ok(status)
    }

    async fn pay_invoice(
        &self,
        invoice: Bolt11Invoice,
        _max_fee: Option<Amount>,
    ) -> Result<(String, Amount), Error> {
        let payment_hash =
            self.node
                .send_payment(&ldk_node::lightning_invoice::Bolt11Invoice::from_str(
                    &invoice.to_string(),
                )?)?;
        let payment = self
            .node
            .list_payments_with_filter(|p| p.hash == payment_hash);

        let amount_msat = payment[0]
            .amount_msat
            .map(|a| Amount::from_msat(a))
            .unwrap_or_default();

        Ok((String::from_utf8(payment_hash.0.to_vec())?, amount_msat))
    }
}

#[async_trait]
impl LnNodeManager for Ldk {
    async fn new_onchain_address(&self) -> Result<Address, Error> {
        let address = self.node.new_onchain_address()?;

        let address = Address::from_str(&address.to_string())?.assume_checked();

        Ok(address)
    }

    async fn open_channel(
        &self,
        open_channel_request: requests::OpenChannelRequest,
    ) -> Result<String, Error> {
        let requests::OpenChannelRequest {
            public_key,
            host,
            port,
            amount,
            push_amount,
        } = open_channel_request;

        let peer_ip = Ipv4Addr::from_str(&host)?;

        let peer_addr = SocketAddr::new(std::net::IpAddr::V4(peer_ip), port);

        let net_address = NetAddress::from(peer_addr);
        let node_pubkey =
            ldk_node::bitcoin::secp256k1::PublicKey::from_slice(&public_key.serialize())?;

        let push_amount = push_amount.map(|a| a.to_msat());
        let _ = self.node.connect_open_channel(
            node_pubkey,
            net_address,
            amount.into(),
            push_amount,
            None,
            true,
        );

        // TODO: return correct string
        Ok("".to_string())
    }

    async fn list_channels(&self) -> Result<Vec<responses::ChannelInfo>, Error> {
        let channels_details = self.node.list_channels();

        let channel_info = channels_details
            .into_iter()
            .flat_map(channel_info_from_details)
            .collect();

        Ok(channel_info)
    }

    async fn get_balance(&self) -> Result<responses::BalanceResponse, Error> {
        let on_chain_total = Amount::from_sat(self.node.total_onchain_balance_sats()?);
        let on_chain_spendable = Amount::from_sat(
            self.node
                .spendable_onchain_balance_sats()
                .unwrap_or_default(),
        );
        let channel_info = self.node.list_channels();

        let ln = channel_info.into_iter().fold(Amount::ZERO, |acc, c| {
            Amount::from_msat(c.balance_msat) + acc
        });

        Ok(responses::BalanceResponse {
            on_chain_total,
            on_chain_spendable,
            ln,
        })
    }

    async fn pay_invoice(&self, bolt11: Bolt11) -> Result<responses::PayInvoiceResponse, Error> {
        let p = bolt11.bolt11.payment_hash();

        let _res =
            self.node
                .send_payment(&ldk_node::lightning_invoice::Bolt11Invoice::from_str(
                    &bolt11.bolt11.to_string(),
                )?)?;

        let res = responses::PayInvoiceResponse {
            payment_preimage: None,
            payment_hash: Sha256::from_str(&p.to_string())?,
            status: InvoiceStatus::InFlight,
        };

        Ok(res)
    }

    async fn create_invoice(
        &self,
        amount: Amount,
        description: String,
    ) -> Result<Bolt11Invoice, Error> {
        let invoice = self
            .node
            .receive_payment(amount.to_msat(), &description, SECS_IN_DAY)?;

        Ok(invoice)
    }

    async fn pay_on_chain(&self, address: Address, amount: Amount) -> Result<String, Error> {
        let address = gl_client::bitcoin::Address::from_str(&address.to_string())?;
        let res = self
            .node
            .send_to_onchain_address(&address, amount.to_sat())?;

        Ok(res.to_string())
    }

    async fn close(&self, channel_id: String, peer_id: Option<PublicKey>) -> Result<(), Error> {
        let channel_id: [u8; 32] = channel_id.as_bytes().try_into()?;
        let channel_id = ChannelId(channel_id);

        let peer_id = peer_id
            .map(|id| id.to_string())
            .ok_or_else(|| Error::Custom("Peer id is required".to_string()))?;

        let peer_id = cln_rpc::primitives::PublicKey::from_str(&peer_id)?;

        self.node.close_channel(&channel_id, peer_id)?;

        Ok(())
    }

    async fn pay_keysend(
        &self,
        destination: bitcoin::secp256k1::PublicKey,
        amount: Amount,
    ) -> Result<String, Error> {
        let pubkey = cln_rpc::primitives::PublicKey::from_slice(&destination.serialize())?;

        let res = self
            .node
            .send_spontaneous_payment(amount.to_sat(), pubkey)?;

        Ok(String::from_utf8(res.0.to_vec())?)
    }

    async fn connect_peer(
        &self,
        public_key: PublicKey,
        address: String,
        port: u16,
    ) -> Result<responses::PeerInfo, Error> {
        let net_addr = NetAddress::from_str(&format!("{}:{}", address, port))?;

        let pubkey = cln_rpc::primitives::PublicKey::from_slice(&public_key.serialize())?;
        self.node.connect(pubkey, net_addr, true)?;

        let peer_info = responses::PeerInfo {
            peer_pubkey: public_key,
            host: address,
            port,
            connected: true,
        };

        Ok(peer_info)
    }

    async fn list_peers(&self) -> Result<Vec<responses::PeerInfo>, Error> {
        let peers = self
            .node
            .list_peers()
            .iter()
            .flat_map(peer_info_from_details)
            .collect();

        Ok(peers)
    }
}

fn channel_info_from_details(details: ChannelDetails) -> Result<ChannelInfo, Error> {
    let peer_pubkey =
        bitcoin::secp256k1::PublicKey::from_str(&details.counterparty_node_id.to_string())?;

    let status = match details.is_usable {
        true => ChannelStatus::Active,
        false => ChannelStatus::Inactive,
    };

    Ok(ChannelInfo {
        peer_pubkey,
        channel_id: String::from_utf8(details.channel_id.0.to_vec())?,
        balance: Amount::from_msat(details.balance_msat),
        value: Amount::from_sat(details.channel_value_sats),
        is_usable: details.is_usable,
        status,
    })
}

fn peer_info_from_details(details: &PeerDetails) -> Result<responses::PeerInfo, Error> {
    let _peer_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&details.node_id.serialize())?;

    todo!()
    /*
    Ok(responses::PeerInfo {
        peer_pubkey,
        host: details.address.0,
        connected: details.is_connected,
    })
    */
}
