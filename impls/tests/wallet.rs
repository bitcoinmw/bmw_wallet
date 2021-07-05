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

fn build_config(dir: &str) -> WalletConfig {
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
		init_args: Some(InitArgs {
			here: true,
			recover: false,
			recover_phrase: None,
		}),
		outputs_args: None,
		send_args: None,
		burn_args: None,
		claim_args: None,
		cancel_args: None,
		account_args: None,
		txs_args: None,
		pass: None,
	};
	config
}

#[test]
fn test_init() {
	let test_dir = ".bmw_wallet_test";
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let mut wallet = get_wallet_instance();
	let config = build_config(test_dir);
	let res = wallet.init(&config, "").unwrap();
	assert_eq!(res.get_mnemonic().is_ok(), true);

	clean_output_dir(test_dir);
	assert!(true);
}
