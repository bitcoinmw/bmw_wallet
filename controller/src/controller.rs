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

use crate::error::Error;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_libwallet::OutputType;
use bmw_wallet_libwallet::TxType;
use bmw_wallet_libwallet::WalletInst;
use bmw_wallet_util::grin_core::core::transaction::KernelFeatures::{Burn, Plain};
use bmw_wallet_util::grin_core::core::OutputFeatures;
use bmw_wallet_util::grin_util::hex::ToHex;
use chrono::prelude::DateTime;
use chrono::Local;
use chrono::Utc;
use colored::Colorize;
use num_format::{Locale, ToFormattedString};
use rpassword::prompt_password_stdout;
use std::time::{Duration, Instant, UNIX_EPOCH};

const BREAKER: &str = "------------------------------------------------";

/// print a yellow break for formatting
fn print_break_line() {
	let twenty_dashes = "--------------------".yellow();
	let seventeen_dashes = "-----------------".yellow();
	println!(
		"{}",
		format!(
			"{}{}{}{}",
			twenty_dashes, twenty_dashes, twenty_dashes, seventeen_dashes
		)
		.yellow()
	);
}

/// print a white break for formatting
fn print_break_line_white() {
	let twenty_dashes = "--------------------";
	let eight_dashes = "--------";
	println!(
		"{}",
		format!(
			"{}{}{}{}{}{}{}",
			twenty_dashes,
			twenty_dashes,
			twenty_dashes,
			twenty_dashes,
			twenty_dashes,
			twenty_dashes,
			eight_dashes,
		)
	);
}

/// main entry point for command line wallet
pub fn run_command(
	config: WalletConfig,
	wallet_inst: &mut (dyn WalletInst + 'static),
) -> Result<(), Error> {
	let mut success = false;
	let start;
	match &config.sub_command[..] {
		"init" => {
			let mut password_match = true;
			let pass = if config.pass.clone().is_some() {
				config.pass.clone().unwrap()
			} else {
				let pass = prompt_password_stdout("Password: ")?;
				let confirm = prompt_password_stdout("Confirm: ")?;
				if confirm != pass {
					password_match = false;
				}
				pass
			};
			start = Instant::now();
			if !password_match {
				println!("Passwords didn't match!");
			} else {
				match wallet_inst.init(&config, &pass) {
					Ok(init_response) => {
						println!(
							"Wallet Seed file created. \
Backup mnemonic phrase:\n{}{}\n[ {} ]\n{}{}",
							BREAKER.yellow(),
							BREAKER.yellow(),
							init_response.get_mnemonic()?,
							BREAKER.yellow(),
							BREAKER.yellow(),
						);
						success = true;
					}
					Err(e) => {
						println!("init command generated error: {}", e.to_string());
					}
				}
			}
		}
		"address" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.address(&config, &pass) {
				Ok(address_response) => {
					print_break_line();
					println!("[ {} ]", address_response.get_address()?);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("info command generated error: {}", e.to_string());
				}
			}
		}
		"info" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.info(&config, &pass) {
				Ok(ir) => {
					let balance = ir.get_balance()?;
					let spendable = ir.get_spendable()?;
					println!("{}     {:.9} BMW", "Total Balance:".green(), balance,);
					println!("{}   {:.9} BMW", "Total Spendable:".green(), spendable);
					if balance != spendable {
						println!(
							"{} {:.9} BMW",
							"Immature Coinbase:".green(),
							balance - spendable
						);
					}
					println!(
						"{} {}",
						"Blockchain Height:".green(),
						ir.get_height()?.to_formatted_string(&Locale::en)
					);
					println!(
						"{}     {}",
						"Total Outputs:".green(),
						ir.get_output_count()?.to_formatted_string(&Locale::en)
					);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("info command generated error: {}", e.to_string());
				}
			}
		}
		"cancel" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.cancel(&config, &pass) {
				Ok(_) => {
					println!(
						"Cancel complete. Id {} cancelled.",
						config.cancel_args.unwrap().id
					);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("cancel command generated error: {}", e.to_string());
				}
			}
		}
		"outputs" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.outputs(&config, &pass) {
				Ok(outputs_response) => {
					let output_vec = outputs_response.get_outputs_data()?;
					let cur_height = outputs_response.get_height()?;
					let mut itt = 0;
					for output_data in &output_vec {
						let commit = if output_data.output_type == OutputType::Spent
							|| output_data.output_type == OutputType::PossibleReorg
						{
							output_data.output.identifier.commit.as_ref().to_hex().red()
						} else if itt % 2 == 0 {
							output_data
								.output
								.identifier
								.commit
								.as_ref()
								.to_hex()
								.green()
						} else {
							output_data
								.output
								.identifier
								.commit
								.as_ref()
								.to_hex()
								.cyan()
						};

						let features = if itt % 2 == 0 {
							if output_data.output.identifier.features == OutputFeatures::Coinbase {
								"Coinbase".green()
							} else {
								match output_data.output_type {
									OutputType::Payment => "Received".green(),
									OutputType::Change => " Change ".green(),
									OutputType::Spent => " Spent ".red(),
									_ => "Unknown".green(),
								}
							}
						} else {
							if output_data.output.identifier.features == OutputFeatures::Coinbase {
								"Coinbase".cyan()
							} else {
								match output_data.output_type {
									OutputType::Payment => "Received".cyan(),
									OutputType::Change => " Change ".cyan(),
									OutputType::Spent => " Spent ".red(),
									_ => "Unknown".cyan(),
								}
							}
						};
						let locked_string = if output_data.lock_height > cur_height + 1 {
							let rem = (output_data.lock_height - cur_height) - 1;
							let indent_adjust = if rem < 10 {
								"   "
							} else if rem < 100 {
								"  "
							} else if rem < 1000 {
								" "
							} else {
								""
							};
							format!(
								"{}{}",
								indent_adjust,
								format!("    (LOCKED - {} blocks)", rem).bright_red()
							)
						} else {
							format!("")
						};

						println!("{} ({})", commit, features);
						let mut value_str =
							format!("{:.9} BMW", output_data.value as f64 / 1_000_000_000 as f64);

						loop {
							if value_str.len() < 20 {
								value_str = format!("{} ", value_str);
							} else {
								break;
							}
						}

						let confirmations = 1 + (cur_height - output_data.height);
						let mut first_part_of_line = format!(
							"Value: {} Confirmations: {}",
							value_str,
							confirmations.to_formatted_string(&Locale::en),
						);

						if confirmations < 1000 {
							first_part_of_line = format!("{}  ", first_part_of_line);
						}
						if confirmations < 100 {
							first_part_of_line = format!("{} ", first_part_of_line);
						}
						if confirmations < 10 {
							first_part_of_line = format!("{} ", first_part_of_line);
						}

						println!("{}   {}", first_part_of_line, locked_string);

						let d = UNIX_EPOCH + Duration::from_secs(output_data.timestamp / 1000);
						let datetime = DateTime::<Utc>::from(d).with_timezone(&Local);
						let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S %z").to_string();
						if output_data.output_type == OutputType::Spent {
							println!(
								"Time Received: {}.         PaymentId: {}",
								timestamp_str,
								format!("{}", output_data.payment_id).red()
							);
						} else if itt % 2 == 0 {
							println!(
								"Time Received: {}.         PaymentId: {}",
								timestamp_str,
								format!("{}", output_data.payment_id).green()
							);
						} else {
							println!(
								"Time Received: {}.         PaymentId: {}",
								timestamp_str,
								format!("{}", output_data.payment_id).cyan()
							);
						}
						print_break_line();
						itt += 1;
					}
					println!(
						"Outputs at block height: {}. Total Outputs: {}",
						cur_height.to_formatted_string(&Locale::en),
						output_vec.len().to_formatted_string(&Locale::en),
					);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("outputs command generated error: {}", e.to_string());
				}
			}
		}
		"account" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.account(&config, &pass) {
				Ok(account_response) => {
					let created = account_response.created()?;
					if created.is_some() {
						let created = created.as_ref().unwrap();
						print_break_line();
						println!(
							"{}: [{}]",
							created.name.green(),
							format!("{}", created.index).cyan()
						);
						print_break_line();
						success = true;
					} else {
						print_break_line();
						let mut max_len = 1;
						for account_vec in account_response.accounts() {
							for account in account_vec {
								if account.name.len() > max_len {
									max_len = account.name.len();
								}
							}
						}

						for account_vec in account_response.accounts() {
							for account in account_vec {
								let space_len = max_len - account.name.len();
								let mut spaces = "".to_string();
								for _ in 0..space_len {
									spaces = format!(" {}", spaces);
								}
								println!(
									"{}{}: [{}]",
									account.name.green(),
									spaces,
									format!("{}", account.index).cyan()
								);
							}
						}
						print_break_line();
						success = true;
					}
				}
				Err(e) => {
					println!("account command generated error: {}", e.to_string());
				}
			}
		}
		"txs" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.txs(&config, &pass) {
				Ok(txs_response) => {
					let txs = txs_response.tx_entries()?;
					let timestamps = txs_response.get_timestamps()?;
					let height = txs_response.get_height()?;
					let mut cumulative_balance = 0;
					let mut max_id_len = 4;
					for tx in &txs {
						let len = format!("{}", tx.id).len();
						if len > max_id_len {
							max_id_len = len;
						}
					}

					let mut id_gap = "".to_string();
					for _ in 2..max_id_len {
						id_gap = format!("{} ", id_gap);
					}
					println!(
						"ID{} PAYMENT_ID       TYPE              DEBIT            CREDIT           BALANCE          CONFIRMS  TIME",
						id_gap,
					);
					print_break_line_white();
					let is_single = config.txs_args.as_ref().unwrap().tx_id.is_some()
						|| config.txs_args.as_ref().unwrap().payment_id.is_some();
					let mut count = 0;
					for tx in txs {
						let timestamp = timestamps[count];
						let d = UNIX_EPOCH + Duration::from_secs(timestamp / 1000);
						let datetime = DateTime::<Utc>::from(d).with_timezone(&Local);
						let timestamp = if timestamp == 0 {
							"            -".to_string()
						} else {
							datetime.format("(%Y-%m-%d %H:%M:%S %z)").to_string()
						};
						count += 1;
						if count % 20 == 0 {
							println!(
                                                		"ID{} PAYMENT_ID       TYPE              DEBIT            CREDIT           BALANCE          CONFIRMS  TIME",
								id_gap,
                                        		);
							print_break_line_white();
						}
						let debit = if tx.tx_type == TxType::Sent
							|| tx.tx_type == TxType::Burn
							|| tx.tx_type == TxType::SentCancelled
							|| tx.tx_type == TxType::BurnCancelled
							|| tx.tx_type == TxType::UnknownSpend
						{
							let fee = if tx.tx.is_none() {
								0
							} else {
								match tx.tx.as_ref().unwrap().kernels()[0].features {
									Plain { fee, .. } => fee.into(),
									Burn { fee, .. } => fee.into(),
									_ => 0,
								}
							};
							if tx.confirmation_block != u64::MAX {
								cumulative_balance -= tx.amount + fee;
							}
							format!("-{}", (tx.amount + fee) as f64 / 1_000_000_000 as f64)
						} else {
							"-0".to_string()
						};

						let credit = if tx.tx_type == TxType::Sent
							|| tx.tx_type == TxType::Burn
							|| tx.tx_type == TxType::SentCancelled
							|| tx.tx_type == TxType::BurnCancelled
							|| tx.tx_type == TxType::UnknownSpend
						{
							"+0".to_string()
						} else {
							cumulative_balance += tx.amount;
							format!("+{}", tx.amount as f64 / 1_000_000_000 as f64)
						};

						let mut id = format!("{}", tx.id);
						let len = id.len();
						for _ in len..max_id_len {
							id = format!("{} ", id);
						}

						let mut tx_type = format!("{}", tx.tx_type);
						match tx.tx_type {
							TxType::Burn => tx_type = format!("{}             ", tx_type),
							TxType::Claim => tx_type = format!("{}            ", tx_type),
							TxType::Sent => tx_type = format!("{}             ", tx_type),
							TxType::Received => tx_type = format!("{}         ", tx_type),
							TxType::Coinbase => tx_type = format!("{}         ", tx_type),
							TxType::SentCancelled => tx_type = format!("{} ", tx_type),
							TxType::BurnCancelled => tx_type = format!("{} ", tx_type),
							TxType::ClaimCancelled => tx_type = format!("{}", tx_type),
							TxType::PossibleReorg => tx_type = format!("{}", tx_type),
							TxType::UnknownSpend => tx_type = format!("{}    ", tx_type),
						}

						let confirmation_string = if tx.confirmation_block != u64::MAX
							&& tx.tx_type != TxType::UnknownSpend
						{
							format!(
								"{}",
								((height - tx.confirmation_block) + 1)
									.to_formatted_string(&Locale::en)
							)
						} else if tx.tx_type == TxType::UnknownSpend {
							"-        ".to_string()
						} else {
							"ZERO-CONF".to_string()
						};

						let cumulative_balance = if is_single {
							"    -       ".to_string()
						} else if tx.confirmation_block != u64::MAX {
							format!("+{}", cumulative_balance as f64 / 1_000_000_000 as f64)
						} else {
							format!("      -")
						};
						println!(
							"{} {} {} {:16} {:16} {:16} {:9} {}",
							id,
							format!("{}", tx.payment_id).cyan(),
							tx_type.red(),
							debit,
							credit,
							cumulative_balance,
							confirmation_string,
							timestamp,
						);
						print_break_line_white();
						if is_single {
							if tx.tx.is_some() {
								let tx = tx.tx.as_ref().unwrap();
								let inputs = tx.inputs();
								let outputs = tx.outputs();
								println!("Inputs:");
								for commit_wrapper in inputs {
									println!("    {}", commit_wrapper.commitment().to_hex().cyan());
								}
								println!("Outputs:");
								for output in outputs {
									println!("    {}", output.commitment().to_hex().red());
								}
								print_break_line_white();
							} else if tx.output.is_some() {
								let output = tx.output.as_ref().unwrap();
								println!("Outputs:");
								println!("    {}", output.commitment().to_hex().cyan());
								print_break_line_white();
							}
						}
					}
					success = true;
				}
				Err(e) => {
					println!("txs command generated error: {}", e.to_string());
				}
			}
		}
		"burn" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.burn(&config, &pass) {
				Ok(burn_response) => {
					let payment_id = burn_response.get_payment_id()?;
					println!("Burn complete. Payment ID: {}", payment_id);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("burn command generated error: {}", e.to_string());
				}
			}
		}
		"claim" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			let address_type = config.claim_args.as_ref().unwrap().address_type.as_ref();
			let address_type = match address_type {
				Some(atype) => *atype,
				None => 0,
			};

			match wallet_inst.gen_challenge(&config, &pass) {
				Ok(challenge) => {
					println!("challenge: {}", challenge);
					let redeem_script = config.claim_args.as_ref().unwrap().redeem_script.as_ref();
					let redeem_script = match redeem_script {
						Some(redeem_script) => Some((*redeem_script).clone()),
						None => None,
					};

					let mut signature_vec = vec![];
					loop {
						println!("Enter signature below:");
						let stdin = std::io::stdin();
						let mut signature = String::new();
						stdin.read_line(&mut signature)?;

						let signature = signature.replace("\n", "");
						signature_vec.push(signature);

						if redeem_script.is_none() {
							break;
						}

						println!("More signatures? [y/n]");
						let stdin = std::io::stdin();
						let mut yn = String::new();
						stdin.read_line(&mut yn)?;

						if yn != "y\n" {
							break;
						}
					}

					wallet_inst.claim_bmw(
						&config,
						challenge.to_string(),
						signature_vec,
						redeem_script,
						address_type,
						&pass,
					)?;

					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("claim command generated error: {}", e.to_string());
				}
			}
		}
		"send" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.send(&config, &pass) {
				Ok(send_response) => {
					let payment_id = send_response.get_payment_id()?;
					println!("Send complete. Payment ID: {}", payment_id);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("send command generated error: {}", e.to_string());
				}
			}
		}
		"backup" => {
			let pass = config
				.pass
				.clone()
				.unwrap_or(if config.pass.clone().is_none() {
					prompt_password_stdout("Password: ")?
				} else {
					"".to_string()
				});
			start = Instant::now();
			match wallet_inst.backup(&config, &pass) {
				Ok(backup_response) => {
					let mnemonic = backup_response.get_backup_response()?;
					println!("Backup mnemonic phrase:\n[ {} ]", mnemonic);
					print_break_line();
					success = true;
				}
				Err(e) => {
					println!("send command generated error: {}", e.to_string());
				}
			}
		}
		_ => {
			start = Instant::now();
			if config.sub_command.len() == 0 {
				println!("No command specified. For help use --help");
			} else {
				println!("Not implemented");
			}
		}
	}

	if success {
		let duration = start.elapsed().as_millis() as f64 / 1000 as f64;
		println!(
			"{}",
			format!(
				"Command '{}' Completed Successfully in {:.2} seconds!\n",
				config.sub_command, duration,
			)
			.on_truecolor(222, 184, 135)
		);
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use crate::controller::run_command;
	use bmw_wallet_config::config::AccountArgs;
	use bmw_wallet_config::config::BurnArgs;
	use bmw_wallet_config::config::ClaimArgs;
	use bmw_wallet_config::config::InitArgs;
	use bmw_wallet_config::config::OutputsArgs;
	use bmw_wallet_config::config::SendArgs;
	use bmw_wallet_config::config::TxsArgs;
	use bmw_wallet_config::config::WalletConfig;
	use bmw_wallet_impls::wallet::Wallet;
	use bmw_wallet_util::grin_core::global;
	use bmw_wallet_util::grin_core::global::ChainTypes;
	use std::path::PathBuf;

	#[test]
	fn test_init() {
		// basic tests for now just test that everything returns ok.
		// TODO: expand tests
		bmw_wallet_util::grin_util::init_test_logger();
		global::set_local_chain_type(global::ChainTypes::UserTesting);
		let test_dir = ".bmw_wallet_controller_init";
		let mut wallet = get_wallet_instance();
		let mut config = build_config(
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
		config.sub_command = "init".to_string();
		config.pass = Some("".to_string());
		assert!(run_command(config, &mut wallet).is_ok());

		clean_output_dir(test_dir);
	}

	#[test]
	fn test_account() {
		// basic tests for now just test that everything returns ok.
		// TODO: expand tests
		bmw_wallet_util::grin_util::init_test_logger();
		global::set_local_chain_type(global::ChainTypes::UserTesting);
		let test_dir = ".bmw_wallet_controller_account";
		let mut wallet = get_wallet_instance();
		let mut config = build_config(
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
		config.sub_command = "account".to_string();
		config.pass = Some("".to_string());
		assert!(run_command(config, &mut wallet).is_ok());

		clean_output_dir(test_dir);
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

	pub fn clean_output_dir(test_dir: &str) {
		let _ = std::fs::remove_dir_all(test_dir);
	}
}
