use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{ACCESS_CONTROL_ALLOW_CREDENTIALS, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bitcoin::{Address, Network};
use chrono::Duration;
use jwt_compact::{
    alg::{Hs256, Hs256Key},
    prelude::*,
};
use lightning_invoice::Bolt11Invoice;
use ln_rs_models::responses::FundingAddressResponse;
use ln_rs_models::{requests, responses, Amount, Bolt11, TokenClaims};
use nostr::event::Event;
use nostr::key::XOnlyPublicKey;
use std::net::Ipv4Addr;
use tower_http::cors::CorsLayer;
use tracing::warn;

pub use super::error::Error;
use super::jwt_auth::auth;

use crate::LnProcessor;

#[derive(Clone)]
pub struct NodeManger {
    pub ln: Arc<Box<dyn LnProcessor>>,
    pub authorized_users: HashSet<XOnlyPublicKey>,
    pub jwt_secret: String,
}

impl NodeManger {
    pub async fn start_server(
        &self,
        listen_host: &str,
        port: u16,
        authorized_users: HashSet<XOnlyPublicKey>,
        jwt_secret: &str,
    ) -> Result<(), Error> {
        let state = NodeManger {
            ln: self.ln.clone(),
            authorized_users,
            jwt_secret: jwt_secret.to_string(),
        };

        let state_arc = Arc::new(state.clone());
        let node_manager_service = Router::new()
            // Auth Routes
            .route("/nostr-login", post(post_nostr_login))
            .route(
                "/auth",
                post(post_check_auth)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            // Ln Routes
            .route(
                "/fund",
                get(get_funding_address)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/connect-peer",
                post(post_connect_peer)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/peers",
                get(get_peers).route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/open-channel",
                post(post_new_open_channel)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/channels",
                get(get_list_channels)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/balance",
                get(get_balance)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/pay-invoice",
                post(post_pay_invoice)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/pay-keysend",
                post(post_pay_keysend)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/invoice",
                get(get_create_invoice)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/pay-on-chain",
                post(post_pay_on_chain)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            .route(
                "/close",
                post(post_close_channel)
                    .route_layer(middleware::from_fn_with_state(state_arc.clone(), auth)),
            )
            // TODO: Remove this for production
            .layer(
                CorsLayer::very_permissive()
                    .allow_credentials(true)
                    .allow_origin("http://127.0.0.1:8080".parse::<HeaderValue>().unwrap())
                    .allow_headers([
                        AUTHORIZATION,
                        CONTENT_TYPE,
                        ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    ]),
            )
            .with_state(state);

        let ip = Ipv4Addr::from_str(listen_host)?;

        let listen_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);

        axum::Server::bind(&listen_addr)
            .serve(node_manager_service.into_make_service())
            .await
            .map_err(|_| Error::Custom("Axum Server".to_string()))?;

        Ok(())
    }

    pub async fn new_onchain_address(&self) -> Result<responses::FundingAddressResponse, Error> {
        let address = self.ln.new_onchain_address().await?;
        Ok(responses::FundingAddressResponse {
            address: address.to_string(),
        })
    }

    pub async fn connect_open_channel(
        &self,
        open_channel_request: requests::OpenChannelRequest,
    ) -> Result<StatusCode, Error> {
        self.ln.open_channel(open_channel_request).await?;
        Ok(StatusCode::OK)
    }

    pub async fn list_channels(&self) -> Result<Vec<responses::ChannelInfo>, Error> {
        let channels = self.ln.list_channels().await?;

        warn!("Channels: {:?}", channels);

        Ok(channels)
    }

    pub async fn get_balance(&self) -> Result<responses::BalanceResponse, Error> {
        self.ln.get_balance().await
    }

    pub async fn pay_invoice(
        &self,
        bolt11: Bolt11Invoice,
        max_fee: Option<Amount>,
    ) -> Result<responses::PayInvoiceResponse, Error> {
        self.ln.pay_invoice(bolt11, max_fee).await
    }

    pub async fn pay_keysend(
        &self,
        keysend_request: requests::KeysendRequest,
    ) -> Result<String, Error> {
        let amount = Amount::from_sat(keysend_request.amount);

        self.ln.pay_keysend(keysend_request.pubkey, amount).await
    }

    pub async fn create_invoice(
        &self,
        create_invoice_request: requests::CreateInvoiceParams,
    ) -> Result<Bolt11, Error> {
        let requests::CreateInvoiceParams { msat, description } = create_invoice_request;

        let description = match description {
            Some(des) => des,
            None => {
                // TODO: Get default from config
                "Hello World".to_string()
            }
        };

        let amount = Amount::from_msat(msat);

        let invoice = self.ln.create_invoice(amount, description).await?;

        Ok(Bolt11 { bolt11: invoice })
    }

    pub async fn send_to_onchain_address(
        &self,
        create_invoice_request: requests::PayOnChainRequest,
    ) -> Result<String, Error> {
        let amount = Amount::from_sat(create_invoice_request.sat);
        let address = Address::from_str(&create_invoice_request.address)?.assume_checked();

        let txid = self.ln.pay_on_chain(address, amount).await?;

        Ok(txid)
    }

    pub async fn connect_peer(
        &self,
        connect_request: requests::ConnectPeerRequest,
    ) -> Result<responses::PeerInfo, Error> {
        let requests::ConnectPeerRequest {
            public_key,
            host,
            port,
        } = connect_request;

        self.ln.connect_peer(public_key, host, port).await
    }

    pub async fn peers(&self) -> Result<Vec<responses::PeerInfo>, Error> {
        self.ln.list_peers().await
    }

    pub async fn close(&self, close_channel_request: requests::CloseChannel) -> Result<(), Error> {
        self.ln
            .close(
                close_channel_request.channel_id,
                close_channel_request.peer_id,
            )
            .await
    }
}

async fn post_nostr_login(
    State(state): State<NodeManger>,
    Json(payload): Json<Event>,
) -> Result<Response<String>, StatusCode> {
    let event = payload;

    event.verify().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let authorized_users = state.authorized_users;

    if !authorized_users.contains(&event.pubkey) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let claims = TokenClaims {
        sub: event.pubkey.to_string(),
    };

    let time_options = TimeOptions::default();

    let claims = Claims::new(claims).set_duration_and_issuance(&time_options, Duration::hours(1));

    let key = Hs256Key::new(state.jwt_secret);
    let header: Header = Header::default();
    let token: String = Hs256
        .token(&header, &claims, &key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie = Cookie::build("token", token.to_owned())
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(
        responses::LoginResponse {
            status: "OK".to_string(),
            token,
        }
        .as_json()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok(response)
}

#[axum::debug_handler]
async fn post_check_auth() -> Result<StatusCode, StatusCode> {
    Ok(StatusCode::OK)
}

async fn post_connect_peer(
    State(state): State<NodeManger>,
    Json(payload): Json<requests::ConnectPeerRequest>,
) -> Result<StatusCode, Error> {
    let _res = state
        .ln
        .connect_peer(payload.public_key, payload.host, payload.port)
        .await;
    Ok(StatusCode::OK)
}

async fn get_peers(
    State(state): State<NodeManger>,
) -> Result<Json<Vec<responses::PeerInfo>>, Error> {
    let peer_info = state.ln.list_peers().await?;

    Ok(Json(peer_info))
}

async fn post_close_channel(
    State(state): State<NodeManger>,
    Json(payload): Json<requests::CloseChannel>,
) -> Result<StatusCode, Error> {
    state.ln.close(payload.channel_id, payload.peer_id).await?;

    Ok(StatusCode::OK)
}

async fn post_pay_keysend(
    State(state): State<NodeManger>,
    Json(payload): Json<requests::KeysendRequest>,
) -> Result<Json<String>, Error> {
    let res = state
        .ln
        .pay_keysend(payload.pubkey, Amount::from_sat(payload.amount))
        .await?;

    Ok(Json(res))
}

async fn post_pay_invoice(
    State(state): State<NodeManger>,
    Json(payload): Json<Bolt11>,
) -> Result<Json<responses::PayInvoiceResponse>, Error> {
    let _p = state.ln.pay_invoice(payload.bolt11, None).await?;
    todo!()
    // Ok(Json(p))
}

async fn get_funding_address(
    State(state): State<NodeManger>,
) -> Result<Json<responses::FundingAddressResponse>, Error> {
    let on_chain_address = state.ln.new_onchain_address().await?;

    Ok(Json(FundingAddressResponse {
        address: on_chain_address.to_string(),
    }))
}

async fn post_new_open_channel(
    State(state): State<NodeManger>,
    Json(payload): Json<requests::OpenChannelRequest>,
) -> Result<StatusCode, Error> {
    // TODO: Check if node has sufficient onchain balance

    if let Err(err) = state.ln.open_channel(payload).await {
        warn!("{:?}", err);
    };
    Ok(StatusCode::OK)
}

async fn get_list_channels(
    State(state): State<NodeManger>,
) -> Result<Json<Vec<responses::ChannelInfo>>, Error> {
    let channel_info = state.ln.list_channels().await?;

    Ok(Json(channel_info))
}

async fn get_balance(
    State(state): State<NodeManger>,
) -> Result<Json<responses::BalanceResponse>, Error> {
    let balance = state.ln.get_balance().await?;

    Ok(Json(balance))
}

async fn get_create_invoice(
    State(state): State<NodeManger>,
    Query(params): Query<requests::CreateInvoiceParams>,
) -> Result<Json<Bolt11Invoice>, Error> {
    let bolt11 = state
        .ln
        .create_invoice(
            Amount::from_msat(params.msat),
            params.description.unwrap_or_default(),
        )
        .await?;
    Ok(Json(bolt11))
}

async fn post_pay_on_chain(
    State(state): State<NodeManger>,
    Json(payload): Json<requests::PayOnChainRequest>,
) -> Result<Json<String>, Error> {
    // TOD0: Network should be configurable
    let res = state
        .ln
        .pay_on_chain(
            Address::from_str(&payload.address)?.require_network(Network::Bitcoin)?,
            Amount::from_sat(payload.sat),
        )
        .await?;

    Ok(Json(res))
}
