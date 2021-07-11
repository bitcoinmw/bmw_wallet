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

use crate::core::address::Address;
use crate::core::libtx::proof;
use crate::core::libtx::proof::PaymentId;
use crate::core::libtx::ProofBuilder;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::libwallet::NodeClient;
use crate::libwallet::OutputData;
use crate::libwallet::OutputType;
use crate::libwallet::TxType;
use crate::wallet::SortType;
use crate::wallet::Wallet;
use crate::wallet::WalletContext;
use crate::HTTPNodeClient;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_util::grin_core::core::transaction::OutputFeatures;
use bmw_wallet_util::grin_keychain::Keychain;
use bmw_wallet_util::grin_keychain::SwitchCommitmentType;
use bmw_wallet_util::grin_store::lmdb::Store;
use bmw_wallet_util::grin_util::secp::key::PublicKey;
use bmw_wallet_util::grin_util::secp::pedersen::Commitment;
use colored::Colorize;
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

const BATCH_SIZE: u64 = 1000;

/// Scan is called automatically every time the wallet calls a function that requires
/// an updates state. A request to the node is made to check for any new state
/// information
pub fn scan<K, N>(
	ctx: &mut WalletContext<K, N>,
	output_vec: &mut Vec<OutputData>,
	sort_type: SortType,
	max_index: u8,
	is_txs: bool,
) -> Result<(), Error>
where
	K: Keychain,
	N: NodeClient,
{
	let mut mmr_list = vec![];
	let mut mmr_lookup = HashMap::new();
	let mut payment_id_lookup = HashMap::new();
	// setup some maps based on the outputs passed in
	for output in output_vec.clone() {
		if output.output_type == OutputType::Payment
			|| output.output_type == OutputType::Change
			|| output.output_type == OutputType::Coinbase
		{
			mmr_list.push(output.mmr_index);
			mmr_lookup.insert(output.mmr_index, output.clone());
			payment_id_lookup.insert((output.payment_id, output.output.commitment()), output);
		} else if output.output_type == OutputType::ChangeZeroConf {
			payment_id_lookup.insert((output.payment_id, output.output.commitment()), output);
		}
	}

	// get the new headers and outputs, if any, based on the scan
	let (outputs, headers, spent_list) = get_new_outputs_and_headers(
		ctx.wallet,
		ctx.client,
		ctx.keychain,
		ctx.wallet_state_info.sync_headers.to_vec(),
		ctx.config,
		mmr_list,
		max_index,
		payment_id_lookup.clone(),
		ctx.store,
		is_txs,
	)?;

	let wallet = &mut ctx.wallet;

	// insert any new outputs into the store
	for output in outputs {
		wallet.insert_output(output.clone(), ctx.store)?;
		mmr_lookup.insert(output.mmr_index, output);
	}

	let mut remove_list = vec![];
	// add any spent outputs to the remove list
	for mmr_index in spent_list {
		match mmr_lookup.remove(&mmr_index) {
			Some(output) => {
				remove_list.push(output);
			}
			_ => {}
		}
	}

	// update txs
	let mut client = HTTPNodeClient::new(&ctx.config.node, ctx.config.node_api_secret.clone());
	for i in 0..(max_index + 1) {
		let txs = wallet.get_txns_from_db(i, ctx.store)?;
		wallet.check_update_txns(&mut client, txs.clone(), ctx.store)?;
	}

	// remove outputs
	wallet.remove_outputs(remove_list, ctx.store)?;

	output_vec.clear();
	for (_, value) in mmr_lookup {
		output_vec.push(value);
	}

	// sort based on which command is calling us.
	match sort_type {
		SortType::VALUE => output_vec.sort_by_key(|x| x.value),
		SortType::HEIGHT => output_vec.sort_by_key(|x| x.height),
	}

	// update the headers in the db to reflect current state
	ctx.wallet_state_info.sync_headers = headers;
	ctx.wallet
		.update_state_info(ctx.wallet_state_info, ctx.store)?;

	Ok(())
}

/// this fn requests new outputs/headers from the node and updates state
/// appropriately
fn get_new_outputs_and_headers<N, K>(
	wallet: &mut Wallet,
	client: &N,
	keychain: &K,
	sync_headers: Vec<(String, u64, u64)>,
	config: &WalletConfig,
	mmr_list: Vec<u64>,
	max_index: u8,
	payment_id_lookup: HashMap<(PaymentId, Commitment), OutputData>,
	store: &Store,
	is_txs: bool,
) -> Result<(Vec<OutputData>, Vec<(String, u64, u64)>, Vec<u64>), Error>
where
	N: NodeClient,
	K: Keychain,
{
	let builder = ProofBuilder::new(keychain);
	let mut offset = 0;
	let mut max = 1;
	let mut ret_outputs = vec![];
	let mut ret_headers = vec![];

	let mut secret_keys = vec![];
	let mut recipient_addrs = vec![];

	for i in 0..(max_index + 1) {
		let key_id = wallet.get_key_id(i);
		let secret_key = keychain.derive_key(0, &key_id, SwitchCommitmentType::Regular)?;
		let pub_key = PublicKey::from_secret_key(&keychain.secp(), &secret_key)?;
		let recipient_addr = Address::from_one_pubkey(&pub_key, config.chain_type);
		secret_keys.push(secret_key);
		recipient_addrs.push(recipient_addr);
	}

	let mut itt = 0;
	let mut final_height = 0;
	let mut first_height = 0;
	let mut spent_list_ret = vec![];
	let mut printed_progress = false;
	if is_txs {
		println!(
                        "{}",
                        "--------------------------------------------------------------------------------------------------------------------------------".yellow()
                );
	} else {
		println!(
			"{}",
			"-----------------------------------------------------------------------------"
				.yellow()
		);
	}
	loop {
		if offset >= max {
			break;
		}
		let (headers, outputs, is_syncing, spent_list) = if itt == 0 {
			client.scan(sync_headers.clone(), BATCH_SIZE, offset, mmr_list.clone())?
		} else {
			client.scan(sync_headers.clone(), BATCH_SIZE, offset, vec![])?
		};

		if is_syncing {
			return Err(ErrorKind::SyncingError(
				"node is still syncing. Please try again later.".to_string(),
			)
			.into());
		}

		if ret_headers.len() == 0 {
			// only take the first, in the unlikely case there's a reorg during the
			// scan. It would be fixed on the next rescan then.
			ret_headers = headers.clone();
			spent_list_ret = spent_list;
			final_height = if headers.len() > 0 { headers[0].1 } else { 1 };
		}

		for header in &headers {
			if header.2 > max {
				max = header.2;
			}
		}

		for output in &outputs {
			if first_height == 0 {
				first_height = output.1;
				if first_height < headers[0].1 {
					// reorg - need to delete all outputs that are equal to or higher than
					// first height.
					for i in 0..max_index + 1 {
						wallet.delete_outputs_and_txs(first_height, &store, i, config)?;
					}
				}
			}
			let percentage_indicator = if final_height > first_height {
				(output.1 - first_height) as f64 / (final_height - first_height) as f64
			} else {
				1.0
			};
			printed_progress = true;
			let mut percentage_graph = String::from("");
			let mut first_space = false;
			let max = if is_txs { 93 } else { 54 };
			let percentage_display = (percentage_indicator * 100 as f64) as u64;
			for i in 0..max {
				if i as f64 * (100 as f64 / max as f64) < percentage_display as f64 {
					if i == max - 1 {
						percentage_graph.push('>');
					} else {
						percentage_graph.push('=');
					}
				} else {
					if !first_space {
						first_space = true;
						percentage_graph.push('>');
					} else {
						percentage_graph.push(' ');
					}
				}
			}
			print!(
				"\r{} [{}] {}%",
				" Syncing Wallet".cyan(),
				percentage_graph,
				percentage_display
			);

			for account_id in 0..(max_index + 1) {
				let (secret_key, recipient_addr) = {
					let secret_key = &secret_keys[account_id as usize];
					let recipient_addr = &recipient_addrs[account_id as usize];
					(secret_key, recipient_addr)
				};
				// optimization (check view_tag)
				let view_tag = Address::get_view_tag_for_rx(
					keychain.secp(),
					&secret_key,
					&output.2.identifier.nonce,
				)?;
				if view_tag != output.2.identifier.view_tag {
					continue;
				}
				let (ephemeral_key_q, _) = recipient_addr
					.get_ephemeral_key_for_rx(
						keychain.secp(),
						&secret_key,
						&output.2.identifier.nonce,
					)
					.unwrap();

				let commit = output.2.identifier.commit;
				let proof = output.2.proof;
				let res = proof::nit_rewind(
					keychain.secp(),
					&builder,
					commit,
					ephemeral_key_q.clone(),
					None,
					proof,
				)?;

				match res {
					Some((amount, message)) => {
						// this is our output
						let payment_id = message.payment_id;
						let timestamp = message.timestamp;

						let is_coinbase = output.2.identifier.features == OutputFeatures::Coinbase;
						let lock_height = if is_coinbase { output.1 + 1440 } else { 0 };
						let output_type = {
							match payment_id_lookup.get(&(payment_id, output.2.commitment())) {
								Some(t) => {
									let t = t.output_type.clone();
									if t == OutputType::ChangeZeroConf {
										OutputType::Change
									} else if t == OutputType::Spent {
										if is_coinbase {
											let id = wallet.get_next_id(&store, account_id)?;
											wallet.insert_txn(
												None,
												Some(output.2),
												None,
												payment_id,
												SystemTime::now()
													.duration_since(UNIX_EPOCH)
													.unwrap()
													.as_millis() as u64,
												amount,
												TxType::Coinbase,
												id,
												output.1,
												account_id,
												&store,
											)?;
											OutputType::Coinbase
										} else {
											let id = wallet.get_next_id(&store, account_id)?;
											wallet.insert_txn(
												None,
												Some(output.2),
												None,
												payment_id,
												SystemTime::now()
													.duration_since(UNIX_EPOCH)
													.unwrap()
													.as_millis() as u64,
												amount,
												TxType::Received,
												id,
												output.1,
												account_id,
												&store,
											)?;
											OutputType::Payment
										}
									} else {
										if t == OutputType::Payment {
											// re-insert for case of reorg
											let id = wallet.get_next_id(&store, account_id)?;
											wallet.insert_txn(
												None,
												Some(output.2),
												None,
												payment_id,
												SystemTime::now()
													.duration_since(UNIX_EPOCH)
													.unwrap()
													.as_millis() as u64,
												amount,
												TxType::Received,
												id,
												output.1,
												account_id,
												&store,
											)?;
										} else if t == OutputType::Coinbase {
											let id = wallet.get_next_id(&store, account_id)?;
											wallet.insert_txn(
												None,
												Some(output.2),
												None,
												payment_id,
												SystemTime::now()
													.duration_since(UNIX_EPOCH)
													.unwrap()
													.as_millis() as u64,
												amount,
												TxType::Coinbase,
												id,
												output.1,
												account_id,
												&store,
											)?;
										}
										t
									}
								}
								None => {
									if is_coinbase {
										let id = wallet.get_next_id(&store, account_id)?;
										wallet.insert_txn(
											None,
											Some(output.2),
											None,
											payment_id,
											SystemTime::now()
												.duration_since(UNIX_EPOCH)
												.unwrap()
												.as_millis() as u64,
											amount,
											TxType::Coinbase,
											id,
											output.1,
											account_id,
											&store,
										)?;
										OutputType::Coinbase
									} else {
										// must be a new txn, insert it
										let id = wallet.get_next_id(&store, account_id)?;
										wallet.insert_txn(
											None,
											Some(output.2),
											None,
											payment_id,
											SystemTime::now()
												.duration_since(UNIX_EPOCH)
												.unwrap()
												.as_millis() as u64,
											amount,
											TxType::Received,
											id,
											output.1,
											account_id,
											&store,
										)?;
										OutputType::Payment
									}
								}
							}
						};
						ret_outputs.push(OutputData {
							output: output.2,
							payment_id,
							timestamp,
							mmr_index: output.0,
							value: amount,
							height: output.1,
							lock_height,
							is_coinbase,
							account_id,
							output_type,
							is_locked: false,
						});
					}
					_ => {
						// not ours
					}
				}
			}
			offset = output.0 + 1;
			itt += 1;
		}
		// we also break if outputs < BATCH_SIZE because that means we're done
		if outputs.len() < BATCH_SIZE.try_into()? {
			if printed_progress {
				println!("");
				if is_txs {
					println!(
                        			"{}",
                        			"--------------------------------------------------------------------------------------------------------------------------------".yellow()
			                );
				} else {
					println!(
						"{}",
						"-----------------------------------------------------------------------------"
							.yellow()
					);
				}
			}
			break;
		}
	}

	Ok((ret_outputs, ret_headers, spent_list_ret))
}
