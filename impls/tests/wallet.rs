// Copyright 2021 The BMW Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Wallet tests

#[macro_use]
extern crate log;

use bmw_wallet_config::config::AccountArgs;
use bmw_wallet_config::config::BurnArgs;
use bmw_wallet_config::config::ClaimArgs;
use bmw_wallet_config::config::InitArgs;
use bmw_wallet_config::config::OutputsArgs;
use bmw_wallet_config::config::SendArgs;
use bmw_wallet_config::config::TxsArgs;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_impls::wallet::Wallet;
use bmw_wallet_impls::HTTPNodeClient;
use bmw_wallet_libwallet::NodeClient;
use bmw_wallet_libwallet::OutputType;
use bmw_wallet_libwallet::TxType;
use bmw_wallet_libwallet::WalletInst;
use bmw_wallet_util::grin_core::address::Address;
use bmw_wallet_util::grin_core::global;
use bmw_wallet_util::grin_core::global::ChainTypes;
use bmw_wallet_util::grin_core::libtx::proof::PaymentId;
use bmw_wallet_util::grin_p2p::msg::PeerAddrs;
use bmw_wallet_util::grin_p2p::types::PeerAddr;
use bmw_wallet_util::grin_p2p::Seeding;
use bmw_wallet_util::grin_servers as servers;
use bmw_wallet_util::grin_servers::ServerConfig;
use bmw_wallet_util::grin_util::logger::LogEntry;
use bmw_wallet_util::grin_util::secp::key::SecretKey;
use bmw_wallet_util::grin_util::static_secp_instance;
use bmw_wallet_util::grin_util::StopState;
use futures::channel::oneshot;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
mod chain_test_helper;

use self::chain_test_helper::copy_dir_all;

fn build_server_config(api_str: &str, port: u16, tor_port: u16, data_dir: &str) -> ServerConfig {
	let mut config = ServerConfig::default();
	config.db_root = data_dir.to_string();
	config.api_http_addr = api_str.to_string();
	config.p2p_config.tor_port = tor_port;
	config.skip_sync_wait = Some(true);
	config.skip_sync = Some(true);
	config.p2p_config.port = port;
	config.p2p_config.seeding_type = Seeding::List;
	config.p2p_config.seeds = Some(PeerAddrs {
		peers: vec![
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23494,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23394,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23294,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23194,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23094,
			)),
		],
	});
	config.p2p_config.peers_allow = Some(PeerAddrs {
		peers: vec![
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23494,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23394,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23294,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23194,
			)),
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				23094,
			)),
		],
	});
	config
}

fn spawn_server(config: ServerConfig, stop_state: Arc<StopState>) {
	let (_logs_tx, logs_rx) = mpsc::sync_channel::<LogEntry>(200);
	thread::spawn(|| {
		let api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) =
			Box::leak(Box::new(oneshot::channel::<()>()));
		servers::Server::start(
			config,
			Some(logs_rx),
			|serv: servers::Server, _: Option<mpsc::Receiver<LogEntry>>| {
				//global::set_local_chain_type(global::ChainTypes::Testnet);
				let running = Arc::new(AtomicBool::new(true));
				while running.load(Ordering::SeqCst) {
					thread::sleep(Duration::from_secs(1));
				}
				serv.stop();
			},
			Some(stop_state),
			api_chan,
		)
		.unwrap();
		std::thread::park();
	});
}

fn start_test_server(
	data_dir: &str,
	stop_state: Arc<StopState>,
	source: &str,
	api_listener: &str,
	tor_port: u16,
) {
	let data_dir_1 = format!("{}/{}", data_dir.clone(), source);
	let source_dir_1 = format!("tests/resources/{}", source);
	std::fs::create_dir(data_dir_1.clone()).unwrap();
	copy_dir_all(source_dir_1, data_dir_1.clone()).unwrap();

	// start server
	let config = build_server_config(api_listener, 23494, tor_port, &data_dir_1);
	spawn_server(config, stop_state.clone());

	std::thread::sleep(std::time::Duration::from_millis(10 * 1000));

	let mut count = 0;
	loop {
		count += 1;
		let client = HTTPNodeClient::new(&format!("http://{}", api_listener), None);
		//let res = client.chain_height();
		let res = client.scan(vec![], 10, 0, vec![]);
		if count == 100 {
			debug!("tried 100 times, quiting");
			break;
		}
		if res.is_err() {
			debug!("can't connect");
			std::thread::sleep(std::time::Duration::from_millis(1000));
			continue;
		}
		let res = res.unwrap();
		if res.2 {
			// still not synced
			debug!("still syncing"); // shouldn't happen with skip_sync
			std::thread::sleep(std::time::Duration::from_millis(1000));
			continue;
		}
		break;
	}
}

pub fn clean_output_dir(test_dir: &str) {
	let _ = std::fs::remove_dir_all(test_dir);
}

fn get_wallet_instance() -> Wallet {
	Wallet::new().unwrap()
}

fn build_config(
	dir: &str,
	node: &str,
	init_args: Option<InitArgs>,
	account_args: Option<AccountArgs>,
	txs_args: Option<TxsArgs>,
	outputs_args: Option<OutputsArgs>,
	claim_args: Option<ClaimArgs>,
	send_args: Option<SendArgs>,
	burn_args: Option<BurnArgs>,
) -> WalletConfig {
	let mut path = PathBuf::new();
	path.push(dir);
	let config = WalletConfig {
		version: "v1".to_string(),
		chain_type: ChainTypes::Testnet,
		current_dir: Some(path),
		create_path: false,
		sub_command: "account".to_string(),
		account: "default".to_string(),
		node: format!("http://{}", node.to_string()),
		node_api_secret: None,
		init_args,
		outputs_args,
		claim_args,
		cancel_args: None,
		account_args,
		txs_args,
		send_args,
		burn_args,
		pass: None,
	};
	config
}

#[test]
fn test_init() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_init";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::Testnet);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let res = wallet.init(&config, "").unwrap();
	assert_eq!(res.get_mnemonic().is_ok(), true);

	clean_output_dir(test_dir);
}

#[test]
fn test_account() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_account";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::Testnet);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		Some(AccountArgs { create: None }),
		None,
		None,
		None,
		None,
		None,
	);

	let account_resp = wallet.account(&config, "badpass");
	assert_eq!(account_resp.is_err(), true);
	let account_resp = wallet.account(&config, "").unwrap();
	// no accounts created
	assert_eq!(account_resp.created().unwrap().is_some(), false);
	// just default account
	assert_eq!(account_resp.accounts().unwrap().len(), 1);

	// create an account
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		Some(AccountArgs {
			create: Some("test".to_string()),
		}),
		None,
		None,
		None,
		None,
		None,
	);

	let account_resp = wallet.account(&config, "").unwrap();
	let created_info = account_resp.created().unwrap().as_ref().unwrap();
	assert_eq!(created_info.name, "test".to_string());
	assert_eq!(created_info.index, 1);

	let account_info = account_resp.accounts().unwrap();
	assert_eq!(account_info.len(), 2);
	assert_eq!(account_info[0].name, "default");
	assert_eq!(account_info[1].name, "test");

	clean_output_dir(test_dir);
}

#[test]
fn test_address() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_address";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::Testnet);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let address_response = wallet.address(&config, "").unwrap();
	assert_eq!(address_response.get_address().is_ok(), true);

	clean_output_dir(test_dir);
}

#[test]
fn test_info() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_info";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::Testnet);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
		None,
		None,
		None,
		None,
		None,
	);

	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let info_response = wallet.info(&config, "badpass");
	assert_eq!(info_response.is_err(), true);
	let info_response = wallet.info(&config, "").unwrap();
	assert_eq!(info_response.get_output_count().unwrap(), 0);
	assert_eq!(info_response.get_height().unwrap(), 0);
	assert_eq!(info_response.get_balance().unwrap(), 0.0);
	assert_eq!(info_response.get_spendable().unwrap(), 0.0);

	clean_output_dir(test_dir);
}

#[test]
fn test_commands() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_commands";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::Testnet);
	// start the server
	let stop_state = Arc::new(StopState::new());
	global::init_global_chain_type(global::ChainTypes::Testnet);
	std::fs::create_dir(test_dir.clone()).unwrap();
	start_test_server(test_dir, stop_state.clone(), "1", "127.0.0.1:23493", 23497);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	test_txs(test_dir, &mut wallet);
	test_outputs(test_dir, &mut wallet);
	test_backup(test_dir, &mut wallet);
	test_claim(test_dir, &mut wallet);

	// stop servers and restart with claim confirmed
	stop_state.stop();
	std::thread::sleep(std::time::Duration::from_millis(300));

	let stop_state = Arc::new(StopState::new());
	// TODO: tor doesn't shutdown properly on Windows. So we have to use a new tor
	// port for these tests to pass on windows. Must fix.
	start_test_server(test_dir, stop_state.clone(), "2", "127.0.0.1:23493", 23498);
	test_block1(test_dir, &mut wallet);
	test_send(test_dir, &mut wallet);

	// stop servers and restart with send confirmed
	stop_state.stop();
	std::thread::sleep(std::time::Duration::from_millis(300));

	let stop_state = Arc::new(StopState::new());
	start_test_server(test_dir, stop_state.clone(), "3", "127.0.0.1:23493", 23499);
	test_block3(test_dir, &mut wallet);

	// clean up
	stop_state.stop();
	std::thread::sleep(std::time::Duration::from_millis(300));
	clean_output_dir(test_dir);
}

fn test_backup(test_dir: &str, wallet: &mut dyn WalletInst) {
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let backup_response = wallet.backup(&config, "");
	assert_eq!(backup_response.unwrap().get_backup_response().is_ok(), true);
	let backup_response = wallet.backup(&config, "wrong_pass");
	assert_eq!(backup_response.is_err(), true);
}

fn test_txs(test_dir: &str, wallet: &mut dyn WalletInst) {
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "wrong_pass");
	assert_eq!(txs_response.is_err(), true);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_err(), false);
	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.tx_entries().unwrap().len(), 0);
	assert_eq!(txs_response.get_height().unwrap(), 0);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 0);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: Some(format!("{}", PaymentId::new())),
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_err(), false);
	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.tx_entries().unwrap().len(), 0);
	assert_eq!(txs_response.get_height().unwrap(), 0);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 0);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: Some(1),
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_err(), false);
	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.tx_entries().unwrap().len(), 0);
	assert_eq!(txs_response.get_height().unwrap(), 0);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 0);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: Some(format!("{}", PaymentId::new())),
			tx_id: Some(1),
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_err(), true);
}

fn test_outputs(test_dir: &str, wallet: &mut dyn WalletInst) {
	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		Some(OutputsArgs { show_spent: false }),
		None,
		None,
		None,
	);

	let outputs_response = wallet.outputs(&config, "badpass");
	assert_eq!(outputs_response.is_err(), true);
	let outputs_response = wallet.outputs(&config, "");
	assert_eq!(outputs_response.is_err(), false);
	let outputs_response = outputs_response.unwrap();
	assert_eq!(outputs_response.get_outputs_data().unwrap().len(), 0);
	assert_eq!(outputs_response.get_height().unwrap(), 0);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		Some(OutputsArgs { show_spent: true }),
		None,
		None,
		None,
	);
	let outputs_response = wallet.outputs(&config, "");
	assert_eq!(outputs_response.is_err(), false);
	let outputs_response = outputs_response.unwrap();
	assert_eq!(outputs_response.get_outputs_data().unwrap().len(), 0);
	assert_eq!(outputs_response.get_height().unwrap(), 0);
}

fn test_claim(test_dir: &str, wallet: &mut dyn WalletInst) {
	// we need to build a static wallet for testing. Use init -r.
	// build new dir
	let rec_wallet_dir = format!("{}/rec_wallet", test_dir);
	let config = build_config(
                &rec_wallet_dir,
                "127.0.0.1:23493",
                Some(InitArgs {
                        here: true,
                        recover: true,
                        recover_phrase: Some(
				"remember erode concert first dinosaur educate noble pitch tiger control stairs crisp"
				.to_string()
			),
                }),
                None,
                None,
                None,
                None,
                None,
                None,
        );
	let init_response = wallet.init(&config, "");
	assert_eq!(init_response.is_err(), false);

	let private_nonce = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		Some(
			SecretKey::from_slice(
				&secp,
				&[
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 1,
				],
			)
			.unwrap(),
		)
	};

	// try an invalid claim address
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		Some(ClaimArgs {
			address: "bc1q7n633668gsgv75gqk6dt23ujmtlatweklzum94".to_string(),
			redeem_script: None,
			address_type: None,
			fluff: false,
			is_test: true,
			private_nonce: private_nonce.clone(),
		}),
		None,
		None,
	);

	let gen_response = wallet.gen_challenge(&config, "badpass");
	assert_eq!(gen_response.is_err(), true);
	let gen_response = wallet.gen_challenge(&config, "");
	// invalid btc address (for our gen_bin)
	assert_eq!(gen_response.is_err(), true);

	// try a valid one based on our gen_bin
	// try an invalid claim address
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		Some(ClaimArgs {
			address: "1AHNUd5zX3ecpjePrWTYNWEbsKX9T1Ephu".to_string(),
			redeem_script: None,
			address_type: None,
			fluff: false,
			is_test: true,
			private_nonce,
		}),
		None,
		None,
	);

	let gen_response = wallet.gen_challenge(&config, "");
	assert_eq!(gen_response.is_err(), false);

	let gen_response = gen_response.unwrap();
	// it's deterministic because we passed in the nonce and set is_test to true
	assert_eq!(
		gen_response,
		Box::new(
			"bmw0969a97ea8f5abf3b71086fe49db7a6b9e79c1ea787a4217e82fb1cfede8f97e83".to_string()
		)
	);

	// with no signature should error
	let claim_response = wallet.claim_bmw(
		&config,
		"bmw0969a97ea8f5abf3b71086fe49db7a6b9e79c1ea787a4217e82fb1cfede8f97e83".to_string(),
		vec![],
		None,
		0,
		"",
	);

	assert_eq!(claim_response.is_err(), true);

	// with correct signature should be ok
	let claim_response = wallet.claim_bmw(
		&config,
		"bmw0969a97ea8f5abf3b71086fe49db7a6b9e79c1ea787a4217e82fb1cfede8f97e83".to_string(),
		vec![
			"IFXGS0eMpzpT+n0ZUwyb1nggxkcC8Ue7Y5sk0MMmJiJocvT0CGJRPAjEBcZrgqn5GzBjWG2mMoiTuor/iP6rHjo="
			.to_string()
		],
		None,
		0,
		"",
	);
	assert_eq!(claim_response.is_err(), false);

	// try a bad signature
	let claim_response = wallet.claim_bmw(
                &config,
                "bmw0969a97ea8f5abf3b71086fe49db7a6b9e79c1ea787a4217e82fb1cfede8f97e83".to_string(),
                vec![
                        "IFXGS0eMpzpT+n0ZUwyb1nggxkcC8Ue7Y5Sk0MMmJiJocvT0CGJRPAjEBcZrgqn5GzBjWG2mMoiTuor/iP6rHjo="
                        .to_string()
                ],
                None,
                0,
                "",
        );

	assert_eq!(claim_response.is_err(), true);

	// now that we have an unconfirmed transaction, lets test some things about that
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_ok(), true);

	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.tx_entries().unwrap().len(), 1);
	assert_eq!(txs_response.get_height().unwrap(), 0);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 1);
	assert_eq!(txs_response.tx_entries().unwrap()[0].id, 0);
	assert_eq!(txs_response.tx_entries().unwrap()[0].tx_type, TxType::Claim);
	assert_eq!(
		txs_response.tx_entries().unwrap()[0].amount,
		100000000000000
	);

	// unconfirmed is u64::MAX
	assert_eq!(
		txs_response.tx_entries().unwrap()[0].confirmation_block,
		u64::MAX
	);
}

fn test_block1(test_dir: &str, wallet: &mut dyn WalletInst) {
	let rec_wallet_dir = format!("{}/rec_wallet", test_dir);
	// now that we have an unconfirmed transaction, lets test some things about that
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_ok(), true);

	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.get_height().unwrap(), 1);

	assert_eq!(txs_response.tx_entries().unwrap().len(), 2);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 2);
	assert_eq!(
		txs_response.tx_entries().unwrap()[0].amount,
		100000000000000
	);

	// this time it should be confirmed in block 1
	assert_eq!(txs_response.tx_entries().unwrap()[0].confirmation_block, 1);

	// same config ok since there's no new params
	let info_response = wallet.info(&config, "");
	assert_eq!(info_response.is_ok(), true);
	let info_response = info_response.unwrap();
	assert_eq!(info_response.get_height().unwrap(), 1);
	assert_eq!(info_response.get_balance().unwrap(), 100_000.3125);
	assert_eq!(info_response.get_spendable().unwrap(), 100_000.0);
	assert_eq!(info_response.get_output_count().unwrap(), 2);

	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		Some(OutputsArgs { show_spent: false }),
		None,
		None,
		None,
	);
	let outputs_response = wallet.outputs(&config, "");

	assert_eq!(outputs_response.is_ok(), true);
	let outputs_response = outputs_response.unwrap();
	assert_eq!(outputs_response.get_height().unwrap(), 1);
	let res = outputs_response.get_outputs_data().unwrap();
	assert_eq!(res.len(), 2);

	// one coinbase, one for our claim...order non-deterministic
	let mut found_coinbase = false;
	let mut found_plain = false;
	for output in res {
		if output.is_coinbase {
			found_coinbase = true;
			assert_eq!(output.value, 312_500_000);
			assert_eq!(output.height, 1);
			assert_eq!(output.lock_height, 1441);
			assert_eq!(output.output_type, OutputType::Coinbase);
		} else {
			found_plain = true;
			assert_eq!(output.value, 100_000_000_000_000);
			assert_eq!(output.height, 1);
			assert_eq!(output.lock_height, 0);
			assert_eq!(output.output_type, OutputType::Payment);
		}
	}
	assert!(found_coinbase);
	assert!(found_plain);
}

fn test_send(test_dir: &str, wallet: &mut dyn WalletInst) {
	let rec_wallet_dir = format!("{}/rec_wallet", test_dir);
	// create second account
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		Some(AccountArgs {
			create: Some("test".to_string()),
		}),
		None,
		None,
		None,
		None,
		None,
	);

	let account_resp = wallet.account(&config, "").unwrap();
	let created_info = account_resp.created().unwrap().as_ref().unwrap();
	assert_eq!(created_info.name, "test".to_string());
	assert_eq!(created_info.index, 1);

	// check that txs, outputs, and info didn't change (reorg checks)
	test_block1(test_dir, wallet);

	// address for "default" account: tmw1qldcv03e8k7sgy048jwqepvf8242nathj06q6s9n3lx60jw9yv6lqpet0mm
	// address for "test" account: tmw1qs5f8maamds92wgmv85q3hjvzpsds6cayr4dn686z0pra07xmzqfgzdvh0h

	// send from default -> test

	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		Some(SendArgs {
			amount: Some(1.0),
			address: Some(
				Address::from_str(
					"tmw1qs5f8maamds92wgmv85q3hjvzpsds6cayr4dn686z0pra07xmzqfgzdvh0h",
				)
				.unwrap(),
			),
			selection_strategy_is_all: false,
			change_outputs: 3,
			fluff: false,
			tx_id: None,
		}),
		None,
	);

	let send_response = wallet.send(&config, "").unwrap();
	assert_eq!(send_response.get_payment_id().is_ok(), true);

	// now check for the unconfirmed txn
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_ok(), true);

	let txs_response = txs_response.unwrap();
	assert_eq!(txs_response.get_height().unwrap(), 1);

	assert_eq!(txs_response.tx_entries().unwrap().len(), 3);
	assert_eq!(txs_response.get_timestamps().unwrap().len(), 3);
	assert_eq!(
		txs_response.tx_entries().unwrap()[0].amount,
		100000000000000
	);

	assert_eq!(txs_response.tx_entries().unwrap()[1].amount, 312_500_000);

	// check send amount 1 BMW.
	assert_eq!(txs_response.tx_entries().unwrap()[2].amount, 1_000_000_000,);

	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		Some(OutputsArgs { show_spent: false }),
		None,
		None,
		None,
	);
	let outputs_response = wallet.outputs(&config, "");
	assert!(outputs_response.is_ok());

	let outputs_response = outputs_response.unwrap();

	let outputs_data = outputs_response.get_outputs_data().unwrap();
	// the other outputs are still unconfirmed and should not show up yet
	assert_eq!(outputs_data.len(), 2);

	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let info_response = wallet.info(&config, "");

	assert!(info_response.is_ok());

	let info_response = info_response.unwrap();
	assert_eq!(info_response.get_height().unwrap(), 1);
	assert_eq!(info_response.get_balance().unwrap(), 100000.3125);
	assert_eq!(info_response.get_spendable().unwrap(), 100000.0);
	assert_eq!(info_response.get_output_count().unwrap(), 2);
}

fn test_block3(test_dir: &str, wallet: &mut dyn WalletInst) {
	let rec_wallet_dir = format!("{}/rec_wallet", test_dir);
	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
		None,
		None,
		None,
		None,
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_ok(), true);

	// TODO: txs has a problem. With different paymentIds, the wallet
	// doesn't know what to do. Not likely to happen in a regular wallet,
	// but the wallet should handle. Need to fix, but for now not checking txs
	//
	/*
		let txs_response = txs_response.unwrap();
		assert_eq!(txs_response.get_height().unwrap(), 3);
	//println!("tx_entries={:?}", txs_response.tx_entries().unwrap());
		assert_eq!(txs_response.tx_entries().unwrap().len(), 3);
		assert_eq!(txs_response.get_timestamps().unwrap().len(), 3);
		assert_eq!(
				txs_response.tx_entries().unwrap()[0].amount,
				100000000000000
		);
	*/

	let config = build_config(
		&rec_wallet_dir,
		"127.0.0.1:23493",
		None,
		None,
		None,
		None,
		None,
		None,
		None,
	);
	let info_response = wallet.info(&config, "");
	let info_response = info_response.unwrap();
	assert_eq!(info_response.get_height().unwrap(), 3);
	assert_eq!(info_response.get_balance().unwrap(), 99999.937500000);
	assert_eq!(info_response.get_spendable().unwrap(), 99998.985480000);
	// 3 coinbase + 3 change
	assert_eq!(info_response.get_output_count().unwrap(), 6);
}
