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
use bmw_wallet_config::config::InitArgs;
use bmw_wallet_config::config::TxsArgs;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_impls::wallet::Wallet;
use bmw_wallet_impls::HTTPNodeClient;
use bmw_wallet_libwallet::WalletInst;
use bmw_wallet_util::grin_core::global;
use bmw_wallet_util::grin_core::global::ChainTypes;
use bmw_wallet_util::grin_p2p::msg::PeerAddrs;
use bmw_wallet_util::grin_p2p::types::PeerAddr;
use bmw_wallet_util::grin_p2p::Seeding;
use bmw_wallet_util::grin_servers as servers;
use bmw_wallet_util::grin_servers::ServerConfig;
use bmw_wallet_util::grin_util::logger::LogEntry;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
mod chain_test_helper;

use self::chain_test_helper::copy_dir_all;

//use self::chain_test_helper::{build_block, init_chain, mine_chain, new_block};

fn build_server_config(api_str: &str, port: u16, tor_port: u16, data_dir: &str) -> ServerConfig {
	let mut config = ServerConfig::default();
	config.db_root = data_dir.to_string();
	config.api_http_addr = api_str.to_string();
	config.p2p_config.tor_port = tor_port;
	config.skip_sync_wait = Some(true);
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
		],
	});
	config
}

fn spawn_server(config: ServerConfig) {
	let (_logs_tx, logs_rx) = mpsc::sync_channel::<LogEntry>(200);
	thread::spawn(|| {
		servers::Server::start(
			config,
			Some(logs_rx),
			|serv: servers::Server, _: Option<mpsc::Receiver<LogEntry>>| {
				global::set_local_chain_type(global::ChainTypes::UserTesting);
				let running = Arc::new(AtomicBool::new(true));
				let r = running.clone();
				ctrlc::set_handler(move || {
					r.store(false, Ordering::SeqCst);
				})
				.expect("Error setting handler for both SIGINT (Ctrl+C) and SIGTERM (kill)");
				while running.load(Ordering::SeqCst) {
					thread::sleep(Duration::from_secs(1));
				}
				serv.stop();
			},
		)
		.unwrap();
	});
}

fn start_test_server(data_dir: &str) {
	global::init_global_chain_type(global::ChainTypes::UserTesting);

	// start server 1

	let data_dir_1 = format!("{}/1", data_dir.clone());
	println!("dir = {}", data_dir_1);
	error!("dir={}", data_dir_1);
	std::fs::create_dir(data_dir.clone()).unwrap();
	std::fs::create_dir(data_dir_1.clone()).unwrap();
	copy_dir_all("tests/resources/1", data_dir_1.clone()).unwrap();
	let config = build_server_config("127.0.0.1:23493", 23494, 23497, &data_dir_1);
	spawn_server(config);

	// start server 2
	//let config = build_server_config("127.0.0.1:23393", 23394, 23397, "2");
	//spawn_server(config);

	// start server 3
	//let config = build_server_config("127.0.0.1:23293", 23294, 23297, "3");
	//spawn_server(config);

	// start server 4
	//let config = build_server_config("127.0.0.1:23193", 23194, 23197, "4");
	//spawn_server(config);

	std::thread::sleep(std::time::Duration::from_millis(10 * 1000));

	let mut count = 0;
	loop {
		count += 1;
		let client = HTTPNodeClient::new("http://127.0.0.1:23493", None);
		let res = client.chain_height();
		if count == 100 {
			break;
		}
		if res.is_err() {
			debug!("can't connect");
			std::thread::sleep(std::time::Duration::from_millis(1000));
			continue;
		}
		debug!("height: {}", res.unwrap().0);
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
) -> WalletConfig {
	let mut path = PathBuf::new();
	path.push(dir);
	let config = WalletConfig {
		version: "v1".to_string(),
		chain_type: ChainTypes::Mainnet,
		current_dir: Some(path),
		create_path: false,
		sub_command: "account".to_string(),
		account: "default".to_string(),
		node: format!("http://{}", node.to_string()),
		node_api_secret: None,
		init_args,
		outputs_args: None,
		send_args: None,
		burn_args: None,
		claim_args: None,
		cancel_args: None,
		account_args,
		txs_args,
		pass: None,
	};
	config
}

#[test]
fn test_init() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_init";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

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
	);
	let res = wallet.init(&config, "").unwrap();
	assert_eq!(res.get_mnemonic().is_ok(), true);

	clean_output_dir(test_dir);
	assert!(true);
}

#[test]
fn test_account() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_account";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

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
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		Some(AccountArgs { create: None }),
		None,
	);
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
	assert!(true);
}

#[test]
fn test_address() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_address";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

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
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, "127.0.0.1:23493", None, None, None);
	let address_response = wallet.address(&config, "").unwrap();
	assert_eq!(address_response.get_address().is_ok(), true);

	clean_output_dir(test_dir);
}

#[test]
fn test_info() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_info";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

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
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, "127.0.0.1:23493", None, None, None);
	let info_response = wallet.info(&config, "").unwrap();
	assert_eq!(info_response.get_output_count().unwrap(), 0);
	assert_eq!(info_response.get_height().unwrap(), 0);
	assert_eq!(info_response.get_balance().unwrap(), 0.0);
	assert_eq!(info_response.get_spendable().unwrap(), 0.0);

	clean_output_dir(test_dir);
}

#[test]
fn test_txs() {
	bmw_wallet_util::grin_util::init_test_logger();
	let test_dir = ".bmw_wallet_txs";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	// start the server
	start_test_server(test_dir);
	//std::thread::sleep(std::time::Duration::from_millis(10 * 1000));

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
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(
		test_dir,
		"127.0.0.1:23493",
		None,
		None,
		Some(TxsArgs {
			payment_id: None,
			tx_id: None,
		}),
	);
	let txs_response = wallet.txs(&config, "");
	assert_eq!(txs_response.is_err(), false);

	clean_output_dir(test_dir);
}
