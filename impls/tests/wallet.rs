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

use bmw_wallet_config::config::AccountArgs;
use bmw_wallet_config::config::InitArgs;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_impls::wallet::Wallet;
use bmw_wallet_libwallet::WalletInst;
use bmw_wallet_util::grin_core::global;
use bmw_wallet_util::grin_core::global::ChainTypes;
use std::path::PathBuf;

pub fn clean_output_dir(test_dir: &str) {
	let _ = std::fs::remove_dir_all(test_dir);
}

fn get_wallet_instance() -> Wallet {
	Wallet::new().unwrap()
}

fn build_config(
	dir: &str,
	init_args: Option<InitArgs>,
	account_args: Option<AccountArgs>,
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
		node: "".to_string(),
		node_api_secret: None,
		init_args,
		outputs_args: None,
		send_args: None,
		burn_args: None,
		claim_args: None,
		cancel_args: None,
		account_args,
		txs_args: None,
		pass: None,
	};
	config
}

#[test]
fn test_init() {
	let test_dir = ".bmw_wallet_init";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
	);
	let res = wallet.init(&config, "").unwrap();
	assert_eq!(res.get_mnemonic().is_ok(), true);

	clean_output_dir(test_dir);
	assert!(true);
}

#[test]
fn test_account() {
	let test_dir = ".bmw_wallet_account";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, None, Some(AccountArgs { create: None }));
	let account_resp = wallet.account(&config, "").unwrap();
	// no accounts created
	assert_eq!(account_resp.created().unwrap().is_some(), false);
	// just default account
	assert_eq!(account_resp.accounts().unwrap().len(), 1);

	// create an account
	let config = build_config(
		test_dir,
		None,
		Some(AccountArgs {
			create: Some("test".to_string()),
		}),
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
	let test_dir = ".bmw_wallet_address";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, None, None);
	let address_response = wallet.address(&config, "").unwrap();
	assert_eq!(address_response.get_address().is_ok(), true);
}

#[test]
fn test_info() {
	let test_dir = ".bmw_wallet_info";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, None, None);
	let info_response = wallet.info(&config, "").unwrap();
	assert_eq!(info_response.get_output_count().unwrap(), 0);
	assert_eq!(info_response.get_height().unwrap(), 0);
	assert_eq!(info_response.get_balance().unwrap(), 0.0);
	assert_eq!(info_response.get_spendable().unwrap(), 0.0);
}

#[test]
fn test_txs() {
	let test_dir = ".bmw_wallet_txs";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(
		test_dir,
		Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		None,
	);
	let init_resp = wallet.init(&config, "").unwrap();
	assert_eq!(init_resp.get_mnemonic().is_ok(), true);

	let config = build_config(test_dir, None, None);
	let txs_response = wallet.txs(&config, "");
	// TODO: fix, shouldn't be an error
	assert_eq!(txs_response.is_err(), true);
}
