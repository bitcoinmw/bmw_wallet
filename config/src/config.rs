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

use crate::comments::build_toml;
use crate::conf_util::get_bmw_path;
use crate::error::Error;
use crate::error::ErrorKind;
use bmw_wallet_util::grin_core::address::Address;
use bmw_wallet_util::grin_core::global::ChainTypes;
use bmw_wallet_util::grin_core::libtx::proof::PaymentId;
use bmw_wallet_util::grin_util::secp::key::SecretKey;
use clap::load_yaml;
use clap::App;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use toml::Value;
use toml::Value::Table;

const TOML_NAME: &str = "bmw-wallet.toml";

/// Wallet Config object
#[derive(Debug)]
pub struct WalletConfig {
	/// Version pulled in from Cargo.toml files.
	pub version: String,
	/// Chain type Testnet/Mainnet
	pub chain_type: ChainTypes,
	/// Current dir optional parameter
	pub current_dir: Option<PathBuf>,
	/// Whether or not to create path (used by init in some cases)
	pub create_path: bool,
	/// Sub command passed (see bmw.yml)
	pub sub_command: String,
	/// Which account to use for this operation
	pub account: String,
	/// Which node to connect to.
	pub node: String,
	/// API secret for the node.
	pub node_api_secret: Option<String>,
	/// Arguments passed in if this is the init command
	pub init_args: Option<InitArgs>,
	/// Arguments passed in if this is the outputs command
	pub outputs_args: Option<OutputsArgs>,
	/// Arguments passed in if this is the send command
	pub send_args: Option<SendArgs>,
	/// Arguments passed in if this is the burn command
	pub burn_args: Option<BurnArgs>,
	/// Arguments passed in if this is the claims command
	pub claim_args: Option<ClaimArgs>,
	/// Arguments passed in if this is the cancel command
	pub cancel_args: Option<CancelArgs>,
	/// Arguments passed in if this is the account command
	pub account_args: Option<AccountArgs>,
	/// Arguments passed in if this is the txs command
	pub txs_args: Option<TxsArgs>,
	/// Password
	pub pass: Option<String>,
}

/// Arguments for the init command
#[derive(Debug)]
pub struct InitArgs {
	/// Is this a recover of an existing wallet?
	pub recover: bool,
	/// Is the -h parameter specified to install in cwd?
	pub here: bool,
	/// The recovery phrase
	pub recover_phrase: Option<String>,
}

/// Arguments for the cancel command
#[derive(Debug)]
pub struct CancelArgs {
	/// The tx_id to cancel
	pub id: u32,
}

/// Arguments for the account command
#[derive(Debug)]
pub struct AccountArgs {
	/// The account to create optionally
	pub create: Option<String>,
}

/// Output Arguments
#[derive(Debug)]
pub struct OutputsArgs {
	/// Show spent outputs as well as unspent
	pub show_spent: bool,
}

/// Arguments for the send command
#[derive(Debug)]
pub struct SendArgs {
	/// amount to send
	pub amount: Option<f64>,
	/// Address to send to
	pub address: Option<Address>,
	/// whether or not to use all outputs
	pub selection_strategy_is_all: bool,
	/// how many change outputs
	pub change_outputs: u32,
	/// whether to fluff this transaction
	pub fluff: bool,
	/// the transaction id (used to resubmit a previously created transaction)
	pub tx_id: Option<u32>,
	/// the optional payment_id to use for this transaction
	pub payment_id: Option<PaymentId>,
}

/// Arguments for claim command
#[derive(Debug)]
pub struct ClaimArgs {
	/// Address to claim to
	pub address: String,
	/// The redeem script if this is a script being claimed
	pub redeem_script: Option<String>,
	/// Address type hint
	pub address_type: Option<u8>,
	/// whether to fluff this transaction
	pub fluff: bool,
	/// is this a test (must ONLY be used for testing, removes randomness of challenge)
	pub is_test: bool,
	/// passed in private nonce. Only "is_some" for tests. Production must use None
	pub private_nonce: Option<SecretKey>,
	/// the optional payment_id to use for this transaction
	pub payment_id: Option<PaymentId>,
}

/// Arguments for txs command
#[derive(Debug)]
pub struct TxsArgs {
	/// The tx_id to show
	pub tx_id: Option<u32>,
	/// The payment_id to show
	pub payment_id: Option<String>,
}

/// Arguments for burn command
#[derive(Debug)]
pub struct BurnArgs {
	/// amount
	pub amount: f64,
	/// whether or not to use all as inputs
	pub selection_strategy_is_all: bool,
	/// number of change outputs
	pub change_outputs: u32,
	/// whether to fluff this transaction
	pub fluff: bool,
	/// the optional payment_id to use for this transaction
	pub payment_id: Option<PaymentId>,
}

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

// create the default toml file if it doesn't already exist
// if it exists, return the toml Value.
pub fn try_create_toml(config: &WalletConfig, create_path: bool) -> Result<String, Error> {
	let current_dir = &config.current_dir;

	// check if current directory has a toml
	let toml_location = if current_dir.is_some() {
		let current_dir = current_dir.as_ref().unwrap();
		let mut path_buf = PathBuf::new();
		path_buf.push(current_dir);
		path_buf.push(TOML_NAME);
		path_buf
	} else {
		// use default path
		let mut path_buf = PathBuf::new();
		get_bmw_path(
			&config.chain_type.shortname(),
			config.create_path,
			&mut path_buf,
		)?;
		path_buf.push(TOML_NAME);
		path_buf
	}
	.into_os_string()
	.into_string()
	.unwrap();

	// create if specified
	if !Path::new(&toml_location).exists() && create_path {
		build_toml(toml_location.clone(), config)?;
	}

	let contents = fs::read_to_string(toml_location)?;

	Ok(contents)
}

/// Get a config object to use for all commands
pub fn get_config() -> Result<WalletConfig, Error> {
	// config is based on bmw.yml
	let yml = load_yaml!("bmw.yml");
	let version = built_info::PKG_VERSION.to_string();

	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

	// set chaintype
	let chain_type = if args.is_present("testnet") {
		ChainTypes::Testnet
	} else {
		ChainTypes::Mainnet
	};

	// set pass if specified
	let pass = if args.is_present("pass") {
		Some(args.value_of("pass").unwrap().to_string())
	} else {
		None
	};

	let mut init_args = None;
	let mut outputs_args = None;
	let mut cancel_args = None;
	let mut send_args = None;
	let mut burn_args = None;
	let mut txs_args = None;
	let mut account_args = None;
	let mut claim_args = None;
	let mut current_dir = None;
	let mut create_path = false;

	if args.is_present("top_level_dir") {
		let res = args.value_of("top_level_dir");
		match res {
			Some(d) => {
				current_dir = Some(PathBuf::from(d));
			}
			None => {
				warn!("Argument --top_level_dir needs a value. Defaulting to current directory")
			}
		}
	} else if Path::new("./bmw-wallet.toml").exists() {
		current_dir = Some(PathBuf::from("."));
	}

	let sub_command = args.subcommand();
	// special cases for certain lifecycle commands
	match sub_command {
		("init", Some(init_args_values)) => {
			let mut here = false;
			let mut recover = false;
			let mut recover_phrase = None;
			if init_args_values.is_present("here") {
				here = true;
				current_dir = Some(env::current_dir().unwrap_or_else(|e| {
					panic!("Error creating config file: {}", e,);
				}));
			}
			if init_args_values.is_present("recover") {
				recover = true;
				println!("Input Recovery Phrase: ");
				let stdin = io::stdin();
				recover_phrase = Some(stdin.lock().lines().next().unwrap()?);
			}

			init_args = Some(InitArgs {
				here,
				recover,
				recover_phrase,
			});
			create_path = true;
		}
		("cancel", Some(cancel_args_values)) => match cancel_args_values.value_of("id") {
			Some(id) => {
				cancel_args = Some(CancelArgs {
					id: u32::from_str(id)?,
				});
			}
			None => {
				return Err(ErrorKind::InvalidArgument("id must be specified".to_string()).into());
			}
		},
		("outputs", Some(outputs_args_values)) => {
			outputs_args = Some(OutputsArgs {
				show_spent: outputs_args_values.is_present("show_spent"),
			});
		}
		("txs", Some(txs_args_values)) => {
			let tx_id = match txs_args_values.value_of("id") {
				Some(tx_id) => {
					let conversion = u32::from_str(tx_id);
					if conversion.is_err() {
						return Err(ErrorKind::InvalidArgument("Invalid tx_id".to_string()).into());
					}
					Some(conversion.unwrap())
				}
				None => None,
			};

			let payment_id = match txs_args_values.value_of("paymentid") {
				Some(payment_id) => Some(payment_id.to_string()),
				None => None,
			};

			if tx_id.is_some() && payment_id.is_some() {
				return Err(ErrorKind::InvalidArgument(
					"Only tx_id or payment_id may be specified".to_string(),
				)
				.into());
			}

			txs_args = Some(TxsArgs { tx_id, payment_id });
		}
		("account", Some(account_args_values)) => {
			let create = match account_args_values.value_of("create") {
				Some(account) => Some(account.to_string()),
				None => None,
			};

			account_args = Some(AccountArgs { create });
		}
		("claim", Some(claim_args_values)) => {
			let address = match claim_args_values.value_of("address") {
				Some(address) => address,
				None => {
					return Err(ErrorKind::ArgumentNotFound(
						"address must be specified".to_string(),
					)
					.into());
				}
			}
			.to_string();

			let address_type = match claim_args_values.value_of("adress_type") {
				Some(atype) => Some(atype.parse()?),
				None => None,
			};

			let redeem_script = match claim_args_values.value_of("redeem_script") {
				Some(redeem_script) => Some(redeem_script.to_string()),
				None => None,
			};

			let fluff = claim_args_values.is_present("fluff");

			let payment_id = match claim_args_values.value_of("payment_id") {
				Some(payment_id_value) => Some(PaymentId::from_str(payment_id_value)?),
				None => None,
			};

			claim_args = Some(ClaimArgs {
				address,
				redeem_script,
				address_type,
				fluff,
				is_test: false,
				private_nonce: None,
				payment_id,
			});
		}
		("burn", Some(burn_args_values)) => {
			let amount = match burn_args_values.value_of("amount") {
				Some(amount) => f64::from_str(amount)?,
				None => {
					return Err(ErrorKind::ArgumentNotFound(
						"amount must be specified".to_string(),
					)
					.into());
				}
			};

			let change_outputs = match burn_args_values.value_of("change_outputs") {
				Some(change_outputs_value) => u32::from_str(change_outputs_value)?,
				None => 1,
			};

			let selection_strategy_is_all = match burn_args_values.value_of("selection_strategy") {
				Some(strategy) => {
					if strategy != "all" && strategy != "smallest" {
						return Err(ErrorKind::InvalidArgument(
							"only selection strategy 'all' and 'smallest' are valid".to_string(),
						)
						.into());
					} else {
						strategy == "all"
					}
				}
				None => false,
			};

			let fluff = burn_args_values.is_present("fluff");

			let payment_id = match burn_args_values.value_of("payment_id") {
				Some(payment_id_value) => Some(PaymentId::from_str(payment_id_value)?),
				None => None,
			};

			burn_args = Some(BurnArgs {
				amount,
				change_outputs,
				selection_strategy_is_all,
				fluff,
				payment_id,
			});
		}
		("send", Some(send_args_values)) => {
			let tx_id = match send_args_values.value_of("stored_tx") {
				Some(tx_id) => Some(u32::from_str(tx_id)?),
				None => None,
			};

			let amount = match send_args_values.value_of("amount") {
				Some(amount) => {
					if tx_id.is_some() {
						return Err(ErrorKind::InvalidArgument(
							"only one of stored_tx and amount may be specified".to_string(),
						)
						.into());
					}
					Some(f64::from_str(amount)?)
				}
				None => {
					if tx_id.is_none() {
						return Err(ErrorKind::ArgumentNotFound(
							"amount must be specified".to_string(),
						)
						.into());
					}
					None
				}
			};

			let address = match send_args_values.value_of("address") {
				Some(address) => {
					if tx_id.is_some() {
						return Err(ErrorKind::InvalidArgument(
							"only one of stored_tx and address may be specified".to_string(),
						)
						.into());
					}
					Some(Address::from_str(address)?)
				}
				None => {
					if tx_id.is_none() {
						return Err(ErrorKind::ArgumentNotFound(
							"address must be specified".to_string(),
						)
						.into());
					}
					None
				}
			};

			let change_outputs = match send_args_values.value_of("change_outputs") {
				Some(change_outputs_value) => u32::from_str(change_outputs_value)?,
				None => 1,
			};

			let selection_strategy_is_all = match send_args_values.value_of("selection_strategy") {
				Some(strategy) => {
					if strategy != "all" && strategy != "smallest" {
						return Err(ErrorKind::InvalidArgument(
							"only selection strategy 'all' and 'smallest' are valid".to_string(),
						)
						.into());
					} else {
						strategy == "all"
					}
				}
				None => false,
			};

			let fluff = send_args_values.is_present("fluff");

			let payment_id = match send_args_values.value_of("payment_id") {
				Some(payment_id_value) => Some(PaymentId::from_str(payment_id_value)?),
				None => None,
			};

			send_args = Some(SendArgs {
				amount,
				address,
				change_outputs,
				selection_strategy_is_all,
				fluff,
				tx_id,
				payment_id,
			});
		}
		_ => {}
	}
	let sub_command = sub_command.0.to_string();

	let account = args.value_of("account").unwrap_or("default").to_string();

	let mut config = WalletConfig {
		version,
		chain_type,
		current_dir,
		create_path,
		sub_command: sub_command.clone(),
		account,
		init_args,
		account_args,
		send_args,
		burn_args,
		claim_args,
		txs_args,
		outputs_args,
		cancel_args,
		node: "".to_string(),
		node_api_secret: None,
		pass,
	};

	let value = try_create_toml(&config, create_path)?;
	update_config(&mut config, value)?;

	Ok(config)
}

/// Update the config object based on the passed in value
fn update_config(config: &mut WalletConfig, value: String) -> Result<(), Error> {
	let value = match value.parse::<Value>()? {
		Table(value) => value,
		_ => {
			return Err(ErrorKind::TomlError("Invalid TOML File".to_string()).into());
		}
	};
	let wallet = value.get("wallet");

	let wallet = match wallet {
		Some(wallet) => wallet,
		None => {
			return Err(
				ErrorKind::TomlError("wallet section must be specified".to_string()).into(),
			);
		}
	};

	let chain_type = wallet.get("chain_type");

	config.chain_type = match chain_type {
		Some(chain_type) => match chain_type.as_str() {
			Some(chain_type) => match chain_type {
				"Mainnet" => ChainTypes::Mainnet,
				"Testnet" => ChainTypes::Testnet,
				_ => return Err(ErrorKind::TomlError("Invalid network".to_string()).into()),
			},
			None => {
				return Err(
					ErrorKind::TomlError("chain_type must be specified".to_string()).into(),
				);
			}
		},
		None => {
			return Err(ErrorKind::TomlError("chain_type must be specified".to_string()).into());
		}
	};

	let node = wallet.get("node");
	config.node = match node {
		Some(node) => match node.as_str() {
			Some(node) => node.to_string(),
			None => {
				return Err(ErrorKind::TomlError("node must be specified".to_string()).into());
			}
		},
		None => {
			return Err(ErrorKind::TomlError("node must be specified".to_string()).into());
		}
	};

	let node_api_secret_path = wallet.get("node_api_secret_path");
	config.node_api_secret = match node_api_secret_path {
		Some(node_api_secret_path) => match node_api_secret_path.as_str() {
			Some(node_api_secret_path) => {
				let secret = fs::read_to_string(node_api_secret_path);
				match secret {
					Ok(secret) => Some(secret),
					Err(msg) => {
						println!(
							"WARNING: couldn't read api secret \
due to \"{}\". You may need to update your bmw-wallet.toml file in order to connect to the node.",
							msg
						);
						None
					}
				}
			}
			None => None,
		},
		None => None,
	};

	Ok(())
}
