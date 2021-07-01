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
use crate::core::libtx::build;
use crate::core::libtx::ProofBuilder;
use crate::libwallet::AddressResponse;
use crate::libwallet::NodeClient;
use crate::libwallet::SendResponse;
use crate::libwallet::TxType;
use crate::scan::scan;
use crate::HTTPNodeClient;
use base64::decode;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::recovery::RecoveryId;
use bmw_wallet_config::conf_util::get_data_dir_name;
use bmw_wallet_config::config::WalletConfig;
use bmw_wallet_libwallet as libwallet;
use bmw_wallet_libwallet::InfoResponse;
use bmw_wallet_util::grin_core::core::transaction::build_btc_init_kernel_feature;
use bmw_wallet_util::grin_core::core::transaction::KernelFeatures;
use bmw_wallet_util::grin_core::core::transaction::KernelFeatures::BTCClaim;
use bmw_wallet_util::grin_core::core::transaction::Weighting;
use bmw_wallet_util::grin_core::core::verifier_cache::LruVerifierCache;
use bmw_wallet_util::grin_core::core::Inputs;
use bmw_wallet_util::grin_core::core::Output;
use bmw_wallet_util::grin_core::core::RedeemScript;
use bmw_wallet_util::grin_core::core::Transaction;
use bmw_wallet_util::grin_core::core::TransactionBody;
use bmw_wallet_util::grin_core::global;
use bmw_wallet_util::grin_core::libtx::proof::nit_rewind;
use bmw_wallet_util::grin_core::libtx::proof::PaymentId;
use bmw_wallet_util::grin_core::libtx::reward;
use bmw_wallet_util::grin_core::libtx::tx_fee;
use bmw_wallet_util::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use bmw_wallet_util::grin_keychain::BlindingFactor;
use bmw_wallet_util::grin_keychain::ExtKeychain;
use bmw_wallet_util::grin_keychain::Identifier;
use bmw_wallet_util::grin_keychain::Keychain;
use bmw_wallet_util::grin_keychain::SwitchCommitmentType;
use bmw_wallet_util::grin_util as util;
use bmw_wallet_util::grin_util::secp::constants::PEDERSEN_COMMITMENT_SIZE;
use bmw_wallet_util::grin_util::secp::key::PublicKey;
use bmw_wallet_util::grin_util::secp::key::SecretKey;
use bmw_wallet_util::grin_util::secp::pedersen::Commitment;
use bmw_wallet_util::grin_util::RwLock;
use libwallet::AccountInfo;
use libwallet::AccountResponse;
use libwallet::BackupResponse;
use libwallet::BurnResponse;
use libwallet::InitResponse;
use libwallet::OutputData;
use libwallet::OutputType;
use libwallet::OutputsResponse;
use libwallet::TxEntry;
use libwallet::TxsResponse;
use libwallet::WalletInst;
use rand::thread_rng;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use util::ZeroingString;

use crate::error::Error;
use crate::error::ErrorKind;
use crate::seed::WalletSeed;
use bmw_wallet_util::grin_store::lmdb::Store;

const DB_NAME: &str = "db";
const WALLET_STATE_INFO_KEY: [u8; 1] = [0];
const PAYMENT_ID_LEN: usize = 16;

/// Enum specifying which field to sort outputs by
pub enum SortType {
	VALUE,
	HEIGHT,
}

/// Context to hold state info about the wallet
pub struct WalletContext<'a, K, N>
where
	K: Keychain,
	N: NodeClient,
{
	/// The keychain used in this request
	pub keychain: &'a K,
	/// The nodeclient used in this request
	pub client: &'a N,
	/// The wallet state info
	pub wallet_state_info: &'a mut WalletStateInfo,
	/// The wallet object itself
	pub wallet: &'a mut Wallet,
	/// The config passed into this wallet command
	pub config: &'a WalletConfig,
	/// The lmdb store object
	pub store: &'a Store,
}

impl<'a, K: Keychain, N: NodeClient> WalletContext<'a, K, N> {
	/// Create a new Context
	fn new(
		keychain: &'a K,
		client: &'a N,
		config: &'a WalletConfig,
		wallet: &'a mut Wallet,
		wallet_state_info: &'a mut WalletStateInfo,
		store: &'a Store,
	) -> Result<WalletContext<'a, K, N>, Error> {
		Ok(WalletContext {
			keychain,
			client,
			wallet_state_info,
			wallet,
			config,
			store,
		})
	}
}

#[derive(Debug)]
struct TxWrapper {
	tx: Transaction,
	payment_id: PaymentId,
	amount: u64,
}

impl Writeable for TxWrapper {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.payment_id.write(writer)?;
		self.tx.write(writer)?;
		writer.write_u64(self.amount)?;
		Ok(())
	}
}

impl Readable for TxWrapper {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let payment_id = PaymentId::read(reader)?;
		let tx = Transaction::read(reader)?;
		let amount = reader.read_u64()?;
		Ok(TxWrapper {
			payment_id,
			tx,
			amount,
		})
	}
}

#[derive(Clone)]
pub struct Wallet {}

#[derive(Debug)]
pub struct WalletStateInfo {
	pub sync_headers: Vec<(String, u64, u64)>,
}

impl Writeable for WalletStateInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let len = self.sync_headers.len().try_into()?;
		writer.write_u64(len)?;
		for i in 0..len as usize {
			let header_bytes = self.sync_headers[i].0.as_bytes();
			let len = header_bytes.len();
			if len != 64 {
				return Err(ser::Error::CorruptedData);
			}
			for j in 0..len {
				writer.write_u8(header_bytes[j])?;
			}
			writer.write_u64(self.sync_headers[i].1)?;
			writer.write_u64(self.sync_headers[i].2)?;
		}
		Ok(())
	}
}

impl Readable for WalletStateInfo {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let sync_header_len = reader.read_u64()?;
		let mut sync_headers = vec![];
		for _ in 0..sync_header_len {
			let mut header_bytes = [0 as u8; 64];
			for j in 0..64 as usize {
				header_bytes[j] = reader.read_u8()?;
			}
			let height = reader.read_u64()?;
			let mmr_index = reader.read_u64()?;
			sync_headers.push((
				std::str::from_utf8(&header_bytes)?.to_string(),
				height,
				mmr_index,
			));
		}
		Ok(WalletStateInfo { sync_headers })
	}
}

pub struct InitResponseImpl {
	seed: WalletSeed,
}

impl InitResponse for InitResponseImpl {
	fn get_mnemonic(&self) -> Result<String, libwallet::error::Error> {
		match self.seed.to_mnemonic() {
			Ok(mnemonic) => Ok(mnemonic),
			Err(e) => Err(libwallet::error::ErrorKind::ImplsError(format!("{}", e)).into()),
		}
	}
}

pub struct InfoResponseImpl {
	height: u64,
	balance: f64,
	spendable: f64,
	output_count: u64,
}

impl InfoResponse for InfoResponseImpl {
	fn get_height(&self) -> Result<u64, libwallet::error::Error> {
		Ok(self.height)
	}

	fn get_balance(&self) -> Result<f64, libwallet::error::Error> {
		Ok(self.balance)
	}
	fn get_spendable(&self) -> Result<f64, libwallet::error::Error> {
		Ok(self.spendable)
	}
	fn get_output_count(&self) -> Result<u64, libwallet::error::Error> {
		Ok(self.output_count)
	}
}

pub struct OutputsResponseImpl {
	outputs_vec: Vec<OutputData>,
	height: u64,
}

impl OutputsResponse for OutputsResponseImpl {
	fn get_outputs_data(&self) -> Result<Vec<OutputData>, libwallet::error::Error> {
		Ok(self.outputs_vec.clone())
	}

	fn get_height(&self) -> Result<u64, libwallet::error::Error> {
		Ok(self.height)
	}
}

pub struct AddressResponseImpl {
	address: Address,
}

impl AddressResponse for AddressResponseImpl {
	fn get_address(&self) -> Result<Address, libwallet::error::Error> {
		Ok(self.address.clone())
	}
}

pub struct BackupResponseImpl {
	mnemonic: String,
}

impl BackupResponse for BackupResponseImpl {
	fn get_backup_response(&self) -> Result<String, libwallet::error::Error> {
		Ok(self.mnemonic.clone())
	}
}

pub struct SendResponseImpl {
	payment_id: PaymentId,
}

impl SendResponse for SendResponseImpl {
	fn get_payment_id(&self) -> Result<PaymentId, libwallet::error::Error> {
		Ok(self.payment_id)
	}
}

pub struct BurnResponseImpl {
	payment_id: PaymentId,
}

impl BurnResponse for BurnResponseImpl {
	fn get_payment_id(&self) -> Result<PaymentId, libwallet::error::Error> {
		Ok(self.payment_id)
	}
}

pub struct TxsResponseImpl {
	txs: Vec<TxEntry>,
	height: u64,
	timestamps: Vec<u64>,
}

impl TxsResponse for TxsResponseImpl {
	fn tx_entries(&self) -> Result<Vec<TxEntry>, libwallet::error::Error> {
		Ok(self.txs.clone())
	}

	fn get_height(&self) -> Result<u64, libwallet::error::Error> {
		Ok(self.height)
	}

	fn get_timestamps(&self) -> Result<Vec<u64>, libwallet::error::Error> {
		Ok(self.timestamps.clone())
	}
}

pub struct AccountResponseImpl {
	account_vec: Vec<AccountInfo>,
	created: Option<AccountInfo>,
}

impl AccountResponse for AccountResponseImpl {
	fn created(&self) -> Result<&Option<AccountInfo>, libwallet::error::Error> {
		Ok(&self.created)
	}

	fn accounts(&self) -> Result<&Vec<AccountInfo>, libwallet::error::Error> {
		Ok(&self.account_vec)
	}
}

impl WalletInst for Wallet {
	fn init(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn InitResponse>, libwallet::error::Error> {
		let init_args = config.init_args.as_ref().unwrap();
		let data_dir_name = get_data_dir_name(config)?;

		let password = ZeroingString::from(password);
		let test_mode = false;

		// generate seed file
		let seed = if init_args.recover {
			let recovery_phrase =
				ZeroingString::from(init_args.recover_phrase.as_ref().unwrap().to_string());
			WalletSeed::recover_from_phrase(&data_dir_name, recovery_phrase, password.clone())?;
			WalletSeed::from_file(&data_dir_name, password)
		} else {
			WalletSeed::init_file(&data_dir_name, 16, None, password, test_mode)
		}?;

		// create store
		let store = Store::new(&data_dir_name, None, Some(DB_NAME), None)?;

		// initialize some data
		{
			let batch = store.batch()?;
			batch.put_ser(
				&WALLET_STATE_INFO_KEY,
				&WalletStateInfo {
					sync_headers: vec![],
				},
			)?;
			batch.commit()?;
		}

		Ok(Box::new(InitResponseImpl { seed }))
	}

	fn info(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn InfoResponse>, libwallet::error::Error> {
		// build our Context
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let keychain = self.get_keychain(config, password)?;
		let store = self.open_store(config)?;
		let mut wallet_state_info = self.get_wallet_state_info(&store)?;
		let wallet_clone = &mut self.clone();
		let mut ctx = self.build_context(
			&keychain,
			&client,
			&config,
			wallet_clone,
			&mut wallet_state_info,
			&store,
		)?;
		let (acct_index, max_index) = self.get_acct_index(&config, &store)?;

		let mut outputs = self.get_outputs_from_db(SortType::VALUE, &store)?;
		// we always look for new outputs and reorgs
		let scan_result = scan(&mut ctx, &mut outputs, SortType::VALUE, max_index, false);

		match scan_result {
			Ok(_) => {}
			Err(e) => {
				println!("WARNING: Node may not be up to date due to: {}.", e);
			}
		}

		let height = if ctx.wallet_state_info.sync_headers.len() == 0 {
			0
		} else {
			ctx.wallet_state_info.sync_headers[0].1
		};

		let mut balance = 0;
		let mut spendable = 0;
		let mut output_count = 0;
		for output in &outputs {
			if output.account_id == acct_index
				&& (output.output_type == OutputType::Payment
					|| output.output_type == OutputType::Coinbase
					|| output.output_type == OutputType::Change)
			{
				output_count += 1;
				balance += output.value;
				if output.lock_height <= height {
					spendable += output.value;
				}
			}
		}

		let balance: f64 = balance as f64 / 1_000_000_000 as f64;
		let spendable: f64 = spendable as f64 / 1_000_000_000 as f64;

		Ok(Box::new(InfoResponseImpl {
			height,
			balance,
			spendable,
			output_count,
		}))
	}

	fn outputs(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn OutputsResponse>, libwallet::Error> {
		// build our Context
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let keychain = self.get_keychain(config, password)?;
		let store = self.open_store(config)?;
		let mut wallet_state_info = self.get_wallet_state_info(&store)?;
		let wallet_clone = &mut self.clone();

		let mut ctx = self.build_context(
			&keychain,
			&client,
			&config,
			wallet_clone,
			&mut wallet_state_info,
			&store,
		)?;

		let (acct_index, max_index) = self.get_acct_index(&config, &store)?;
		let mut outputs = self.get_outputs_from_db(SortType::HEIGHT, &store)?;
		// we always look for new outputs and reorgs
		let scan_result = scan(&mut ctx, &mut outputs, SortType::HEIGHT, max_index, false);

		let show_spent = config.outputs_args.as_ref().unwrap().show_spent;

		match scan_result {
			Ok(_) => {}
			Err(e) => {
				println!("WARNING: Node may not be up to date due to: {}.", e);
			}
		}

		let height = if ctx.wallet_state_info.sync_headers.len() == 0 {
			0
		} else {
			ctx.wallet_state_info.sync_headers[0].1
		};

		let mut outputs_vec = vec![];
		for output in outputs {
			if output.account_id == acct_index {
				if output.output_type == OutputType::Payment
					|| output.output_type == OutputType::Coinbase
					|| output.output_type == OutputType::Change
				{
					outputs_vec.push(output);
				}
			}
		}

		// we get all outputs again and add spent if it's 'show_spent'
		if show_spent {
			let outputs = self.get_outputs_from_db(SortType::HEIGHT, &store)?;
			for output in outputs {
				if output.account_id == acct_index
					&& (output.output_type == OutputType::Spent
						|| output.output_type == OutputType::PossibleReorg)
				{
					outputs_vec.push(output);
				}
			}
			outputs_vec.sort_by_key(|x| x.height);
		}

		Ok(Box::new(OutputsResponseImpl {
			height,
			outputs_vec,
		}))
	}

	fn address(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn AddressResponse>, libwallet::Error> {
		let keychain = self.get_keychain(config, password)?;
		let store = self.open_store(config)?;
		let (acct_index, _max_index) = self.get_acct_index(&config, &store)?;
		let key_id = self.get_key_id(acct_index);
		let secret_key = keychain.derive_key(0, &key_id, SwitchCommitmentType::Regular)?;
		let pub_key = PublicKey::from_secret_key(&keychain.secp(), &secret_key)?;
		let address = Address::from_one_pubkey(&pub_key, config.chain_type);

		Ok(Box::new(AddressResponseImpl { address }))
	}

	fn cancel(&mut self, config: &WalletConfig, password: &str) -> Result<(), libwallet::Error> {
		// check password:
		let _ = self.get_keychain(config, password)?;
		let cancel_args = config.cancel_args.as_ref().unwrap();
		let store = self.open_store(config)?;
		let id = cancel_args.id;
		let (acct_index, _max_index) = self.get_acct_index(&config, &store)?;
		let txs = self.get_txns_from_db(acct_index, &store)?;

		for mut tx in txs {
			if tx.id == id {
				if tx.confirmation_block != std::u64::MAX {
					return Err(libwallet::ErrorKind::ImplsError(format!(
						"id '{}' has already confirmed. It cannot be cancelled.",
						id
					))
					.into());
				}

				self.cancel_txn(&mut tx, id, acct_index, &store)?;

				// unlock outputs
				if tx.tx.is_some() {
					self.lock_inputs(tx.tx.unwrap().inputs(), &store, false)?;
				}

				return Ok(());
			}
		}

		Err(libwallet::ErrorKind::ImplsError(format!("id '{}' not found.", id)).into())
	}

	fn send(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn SendResponse>, libwallet::Error> {
		let send_args = config.send_args.as_ref().unwrap();
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let store = self.open_store(config)?;

		if send_args.tx_id.is_some() {
			// this is a repost
			let tx_id = send_args.tx_id.as_ref().unwrap();
			let (acct_index, _max_index) = self.get_acct_index(&config, &store)?;
			let txs = self.get_txns_from_db(acct_index, &store)?;

			for tx in txs {
				if tx.id == *tx_id {
					let payment_id = tx.payment_id;
					if tx.confirmation_block < std::u64::MAX {
						return Err(libwallet::ErrorKind::ImplsError(format!(
							"tx_id '{}' has already confirmed",
							tx_id
						))
						.into());
					}
					let tx = tx.tx;
					if tx.is_none() {
						return Err(libwallet::ErrorKind::ImplsError(format!(
							"tx_id '{}' cannot be posted",
							tx_id
						))
						.into());
					}
					let tx = tx.unwrap();
					client.post_tx(&tx, send_args.fluff)?;
					return Ok(Box::new(SendResponseImpl { payment_id }));
				}
			}

			return Err(
				libwallet::ErrorKind::ImplsError(format!("tx_id '{}' not found", tx_id)).into(),
			);
		}

		// build our Context
		let keychain = self.get_keychain(config, password)?;
		let mut wallet_state_info = self.get_wallet_state_info(&store)?;
		let wallet_clone = &mut self.clone();

		let mut ctx = self.build_context(
			&keychain,
			&client,
			&config,
			wallet_clone,
			&mut wallet_state_info,
			&store,
		)?;

		let mut outputs = self.get_outputs_from_db(SortType::VALUE, &store)?;
		let (acct_index, max_index) = self.get_acct_index(&config, &store)?;

		// we always look for new outputs and reorgs
		let scan_result = scan(&mut ctx, &mut outputs, SortType::VALUE, max_index, false);

		match scan_result {
			Ok(_) => {}
			Err(e) => {
				println!("WARNING: Node may not be up to date due to: {}.", e);
			}
		}

		let outputs = {
			let mut filtered_outputs = vec![];
			for output in outputs {
				if output.account_id == acct_index {
					filtered_outputs.push(output);
				}
			}
			filtered_outputs
		};

		// height is first sync header's height
		let height = ctx.wallet_state_info.sync_headers[0].1;
		let amount = (send_args.amount.unwrap() * 1_000_000_000 as f64) as u64;
		let recipient_address = send_args.address.clone();
		let change_address = self.get_local_address(acct_index, &keychain, config)?;
		let (outputs, fee, change_amount) = self.select_coins_and_fee(
			amount,
			outputs,
			height,
			send_args.change_outputs,
			send_args.selection_strategy_is_all,
		)?;

		let key_id = self.get_key_id(acct_index);
		let pri_view = keychain.derive_key(0, &key_id, SwitchCommitmentType::Regular)?;

		let payment_id = PaymentId::new();
		let tx = self.build_send_transaction(
			&keychain,
			amount,
			fee,
			outputs,
			Some(recipient_address.unwrap()),
			change_address,
			change_amount,
			send_args.change_outputs,
			pri_view,
			payment_id,
			acct_index,
			&store,
		)?;

		tx.validate(
			Weighting::AsTransaction,
			Arc::new(RwLock::new(LruVerifierCache::new())),
			height,
			None,
			None,
		)?;

		// lock inputs
		self.lock_inputs(tx.inputs(), &store, true)?;

		// save
		let id = self.get_next_id(&store, acct_index)?;
		self.insert_txn(
			Some(tx.clone()),
			None,
			payment_id,
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
			amount,
			TxType::Sent,
			id,
			std::u64::MAX,
			acct_index,
			&store,
		)?;

		client.post_tx(&tx, send_args.fluff)?;

		Ok(Box::new(SendResponseImpl { payment_id }))
	}

	fn txs(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn TxsResponse>, libwallet::Error> {
		let mut client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let keychain = self.get_keychain(config, password)?;
		let store = self.open_store(config)?;
		let mut wallet_state_info = self.get_wallet_state_info(&store)?;
		let wallet_clone = &mut self.clone();

		let mut ctx = self.build_context(
			&keychain,
			&client,
			&config,
			wallet_clone,
			&mut wallet_state_info,
			&store,
		)?;

		let mut outputs = self.get_outputs_from_db(SortType::VALUE, &store)?;

		let (acct_index, max_index) = self.get_acct_index(&config, &store)?;
		// we always look for new outputs and reorgs
		let scan_result = scan(&mut ctx, &mut outputs, SortType::VALUE, max_index, true);

		match scan_result {
			Ok(_) => {}
			Err(e) => {
				println!("WARNING: Node may not be up to date due to: {}.", e);
			}
		}

		let height = if ctx.wallet_state_info.sync_headers.len() == 0 {
			0
		} else {
			ctx.wallet_state_info.sync_headers[0].1
		};
		let txs = self.get_txns_from_db(acct_index, &store)?;
		let mut txs = self.check_update_txns(&mut client, txs.clone(), &store)?;
		let txs_args = config.txs_args.as_ref().unwrap();
		if txs_args.payment_id.is_some() && txs_args.tx_id.is_some() {
			return Err(libwallet::ErrorKind::IllegalArgument(
				"only one of payment_id and tx_id may be specified".to_string(),
			)
			.into());
		}
		if txs_args.payment_id.is_some() {
			let payment_id = txs_args.payment_id.as_ref().unwrap();
			let mut filtered_txs = vec![];
			for tx in txs {
				if tx.payment_id.to_string() == *payment_id {
					filtered_txs.push(tx);
				}
			}
			txs = filtered_txs;
		}
		if txs_args.tx_id.is_some() {
			let tx_id = txs_args.tx_id.as_ref().unwrap();
			let mut filtered_txs = vec![];
			for tx in txs {
				if tx.id == *tx_id {
					filtered_txs.push(tx);
				}
			}
			txs = filtered_txs;
		}
		txs.sort_by_key(|x| x.confirmation_block);
		let txs = {
			let mut ret = vec![];

			for tx in &txs {
				if tx.tx_type == TxType::SentCancelled
					|| tx.tx_type == TxType::BurnCancelled
					|| tx.tx_type == TxType::ClaimCancelled
				{
					ret.push(tx.clone());
				}
			}

			for tx in &txs {
				if !(tx.tx_type == TxType::SentCancelled
					|| tx.tx_type == TxType::BurnCancelled
					|| tx.tx_type == TxType::ClaimCancelled)
				{
					ret.push(tx.clone());
				}
			}
			ret
		};

		// get txn timestamps based on outputs (on recovery we may not have some,
		// return u64::MAX in those cases)
		let mut timestamps = vec![];

		for tx in &txs {
			let output = match &tx.tx {
				Some(tx) => {
					if tx.outputs().len() > 0 {
						Some(tx.outputs()[0])
					} else {
						None
					}
				}
				None => match tx.output {
					Some(output) => Some(output),
					None => None,
				},
			};

			match output {
				None => timestamps.push(0),
				Some(output) => {
					timestamps.push(self.get_output_timestamp(output.commitment(), &store)?)
				}
			}
		}

		Ok(Box::new(TxsResponseImpl {
			timestamps,
			txs,
			height,
		}))
	}

	fn burn(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn BurnResponse>, libwallet::Error> {
		// build our Context
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let keychain = self.get_keychain(config, password)?;
		let store = self.open_store(config)?;
		let mut wallet_state_info = self.get_wallet_state_info(&store)?;
		let wallet_clone = &mut self.clone();

		let mut ctx = self.build_context(
			&keychain,
			&client,
			&config,
			wallet_clone,
			&mut wallet_state_info,
			&store,
		)?;

		let mut outputs = self.get_outputs_from_db(SortType::VALUE, &store)?;

		let (acct_index, max_index) = self.get_acct_index(&config, &store)?;
		// we always look for new outputs and reorgs
		let scan_result = scan(&mut ctx, &mut outputs, SortType::VALUE, max_index, false);

		match scan_result {
			Ok(_) => {}
			Err(e) => {
				println!("WARNING: Node may not be up to date due to: {}.", e);
			}
		}

		let outputs = {
			let mut filtered_outputs = vec![];
			for output in outputs {
				if output.account_id == acct_index {
					filtered_outputs.push(output);
				}
			}
			filtered_outputs
		};

		// height is first sync header's height
		let burn_args = ctx.config.burn_args.as_ref().unwrap();

		let height = ctx.wallet_state_info.sync_headers[0].1;
		let amount = (burn_args.amount * 1_000_000_000 as f64) as u64;
		let change_address = self.get_local_address(acct_index, &keychain, config)?;
		let (outputs, fee, change_amount) = self.select_coins_and_fee(
			amount,
			outputs,
			height,
			burn_args.change_outputs,
			burn_args.selection_strategy_is_all,
		)?;

		let key_id = self.get_key_id(acct_index);
		let pri_view = keychain.derive_key(0, &key_id, SwitchCommitmentType::Regular)?;

		let payment_id = PaymentId::new();
		let tx = self.build_send_transaction(
			&keychain,
			amount,
			fee,
			outputs,
			None,
			change_address,
			change_amount,
			burn_args.change_outputs,
			pri_view,
			payment_id,
			acct_index,
			&store,
		)?;

		tx.validate(
			Weighting::AsTransaction,
			Arc::new(RwLock::new(LruVerifierCache::new())),
			height,
			None,
			None,
		)?;

		// lock inputs
		self.lock_inputs(tx.inputs(), &store, true)?;

		// save
		let id = self.get_next_id(&store, acct_index)?;
		self.insert_txn(
			Some(tx.clone()),
			None,
			payment_id,
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
			amount,
			TxType::Burn,
			id,
			std::u64::MAX,
			acct_index,
			&store,
		)?;

		client.post_tx(&tx, burn_args.fluff)?;

		Ok(Box::new(BurnResponseImpl { payment_id }))
	}

	fn backup(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn BackupResponse>, libwallet::Error> {
		let mnemonic = self.get_mnemonic(config, password)?;
		Ok(Box::new(BackupResponseImpl { mnemonic }))
	}

	fn gen_challenge(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<String>, libwallet::Error> {
		let store = self.open_store(config)?;
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let keychain = self.get_keychain(config, password)?;
		let (acct_index, _max_index) = self.get_acct_index(&config, &store)?;

		let claim_args = config.claim_args.as_ref().unwrap();
		let status = client.get_btc_address_status(claim_args.address.clone());

		let status = match status {
			Ok(r) => r,
			Err(e) => {
				return Err(libwallet::ErrorKind::RPCCommunicationError(format!("{}", e)).into());
			}
		};

		if !status.1 {
			return Err(libwallet::ErrorKind::BTCAddressInvalid.into());
		}

		if !status.0 {
			return Err(libwallet::ErrorKind::BTCAddressAlreadyClaimed.into());
		}

		let value = status.2 * 10; // 1 sat = 10 nanoBMWs
		let index = status.3;

		let bmw_address = self.get_local_address(acct_index, &keychain, config)?;

		// create dummy data for this phase
		let data = [0 as u8; 64];
		let sig =
			RecoverableSignature::from_compact(&data, RecoveryId::from_i32(0).unwrap()).unwrap();
		let mut sigs = Vec::new();
		sigs.insert(0, sig);
		let mut btc_recovery_byte_vec = Vec::new();
		btc_recovery_byte_vec.insert(0, 0);
		let payment_id = PaymentId::new();

		let (out, kern) = reward::output_btc_claim(
			&keychain,
			&ProofBuilder::new(&keychain),
			bmw_address,
			0,
			false,
			value,
			index,
			sigs,
			btc_recovery_byte_vec,
			None,
			0,
			None,
			payment_id,
		)?;

		let tx = Transaction {
			offset: BlindingFactor::zero(),
			body: TransactionBody {
				inputs: Inputs::default(),
				outputs: vec![out],
				kernels: vec![kern],
			},
		};

		let excess = format!("{:?}", tx.body.kernels[0].excess);
		let excess = excess.replace("Commitment(", "");
		let excess = excess.replace(")", "");
		let challenge = format!("bmw{}", excess);

		// now store challenge into db.
		// note that all challenged begin with 'b'

		{
			let batch = store.batch()?;

			let challenge_bytes = challenge.as_bytes();
			let tx_wrapper = TxWrapper {
				payment_id,
				tx,
				amount: value,
			};
			batch.put_ser(&challenge_bytes, &tx_wrapper)?;
			batch.commit()?;
		}

		Ok(Box::new(challenge))
	}

	fn claim_bmw(
		&mut self,
		config: &WalletConfig,
		challenge: String,
		signatures: Vec<String>,
		redeem_script: Option<String>,
		address_type: u8,
	) -> Result<(), libwallet::Error> {
		let client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let store = self.open_store(config)?;
		let (acct_index, _max_index) = self.get_acct_index(&config, &store)?;

		let mut btc_sigs = vec![];
		let mut btc_recovery_bytes = vec![];

		let challenge_bytes = challenge.as_bytes();

		for signature in signatures {
			let signature = match decode(&signature) {
				Ok(signature) => signature,
				Err(e) => {
					return Err(libwallet::error::ErrorKind::InternalError(e.to_string()).into())
				}
			};
			let recid = RecoveryId::from_i32(i32::from((signature[0] - 27) & 3))?;
			let recsig = RecoverableSignature::from_compact(&signature[1..], recid)?;
			btc_sigs.push(recsig);
			btc_recovery_bytes.push(signature[0]);
		}

		let batch = store.batch()?;

		let claim_args = config.claim_args.as_ref().unwrap();

		let tx_wrapper: Option<TxWrapper> = batch.get_ser(&challenge_bytes)?;

		let (mut tx, payment_id, amount) = match tx_wrapper {
			Some(wrapper) => (wrapper.tx, wrapper.payment_id, wrapper.amount),
			None => {
				return Err(bmw_wallet_libwallet::error::ErrorKind::StoreError(
					"Couldn't retreive tx info".to_string(),
				)
				.into());
			}
		};

		let mut kernel = tx.kernels()[0].clone();
		kernel.features = match kernel.features {
			BTCClaim { fee, index, .. } => {
				let redeem_script = if redeem_script.is_some() {
					let redeem_string = redeem_script.unwrap();
					if redeem_string.len() > 520 {
						return Err(libwallet::error::ErrorKind::RedeemScriptNonStandard.into());
					}
					let data_hex = hex::decode(redeem_string);
					if data_hex.is_err() {
						return Err(libwallet::error::ErrorKind::InvalidRedeemScript.into());
					}
					let mut data_hex = data_hex.unwrap();
					data_hex.resize(520, 97);
					let len = data_hex.len();
					let mut data = [0 as u8; 520];
					data.copy_from_slice(&*data_hex);
					Some(RedeemScript { data, len })
				} else {
					None
				};
				match build_btc_init_kernel_feature(
					fee,
					index,
					btc_sigs,
					btc_recovery_bytes,
					redeem_script,
					address_type,
				) {
					Ok(kf) => kf,
					Err(_e) => return Err(libwallet::ErrorKind::BTCSignatureInvalid.into()),
				}
			}
			_ => {
				return Err(bmw_wallet_libwallet::error::ErrorKind::ImplsError(
					"Incorrect Kernel".to_string(),
				)
				.into());
			}
		};

		tx = tx.replace_kernel(kernel);

		// save
		let id = self.get_next_id(&store, acct_index)?;
		self.insert_txn(
			Some(tx.clone()),
			None,
			payment_id,
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
			amount,
			TxType::Claim,
			id,
			std::u64::MAX,
			acct_index,
			&store,
		)?;

		client.post_tx(&tx, claim_args.fluff)?;

		Ok(())
	}

	fn account(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn AccountResponse>, libwallet::Error> {
		// check password:
		let _ = self.get_keychain(config, password)?;

		// load accounts from db
		let store = self.open_store(config)?;

		let mut account_vec = {
			let iter = {
				let batch = store.batch()?;
				// prefix with 2u8
				let iter = batch.iter(&[2u8], |_, v| {
					let account_result: Result<AccountInfo, ser::Error> =
						ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2))
							.map_err(From::from);
					Ok(account_result)
				});
				batch.commit()?;
				iter
			};

			let mut account_vec = vec![];
			for mut v in iter {
				loop {
					match v.next() {
						Some(account_result) => account_vec.push(account_result?),
						None => break,
					}
				}
			}
			account_vec
		};

		account_vec.push(AccountInfo {
			name: "default".to_string(),
			index: 0,
		});

		account_vec.sort_by_key(|x| x.index);

		if config.account_args.is_none() {
			return Err(libwallet::error::ErrorKind::AccountError(
				"account args not specified".to_string(),
			)
			.into());
		}

		let account_args = &config.account_args.as_ref().unwrap();
		let mut created = None;

		if account_args.create.is_some() {
			let name = account_args.create.as_ref().unwrap().to_string();

			if name == "default" {
				return Err(libwallet::error::ErrorKind::AccountError(
					"cannot create an account named 'default'".to_string(),
				)
				.into());
			}

			for item in &account_vec {
				if *name == item.name {
					return Err(libwallet::error::ErrorKind::AccountError(
						"This account name already exists".to_string(),
					)
					.into());
				}
			}

			let index = account_vec.len();

			if index > u8::MAX.into() {
				return Err(libwallet::error::ErrorKind::AccountError(
					"Too many accounts. Maximum is 256.".to_string(),
				)
				.into());
			}

			let index: u8 = index.try_into()?;

			let new_account_info = AccountInfo { name, index };

			account_vec.push(new_account_info.clone());
			created = Some(new_account_info.clone());

			// put in db
			let batch = store.batch()?;
			batch.put_ser(&[2u8, index], &new_account_info)?;

			// reset sync headers to do a full sync
			batch.delete(&WALLET_STATE_INFO_KEY)?;
			batch.put_ser(
				&WALLET_STATE_INFO_KEY,
				&WalletStateInfo {
					sync_headers: vec![],
				},
			)?;
			batch.commit()?;
		}

		Ok(Box::new(AccountResponseImpl {
			account_vec,
			created,
		}))
	}
}

impl Wallet {
	pub fn new() -> Result<Wallet, Error> {
		Ok(Wallet {})
	}

	pub fn get_wallet_state_info(&mut self, store: &Store) -> Result<WalletStateInfo, Error> {
		let wallet_state_info: Option<WalletStateInfo> =
			store.batch()?.get_ser(&WALLET_STATE_INFO_KEY)?;

		if wallet_state_info.is_none() {
			return Err(bmw_wallet_libwallet::error::ErrorKind::StoreError(
				"Couldn't retreive wallet state info".to_string(),
			)
			.into());
		}

		Ok(wallet_state_info.unwrap())
	}

	fn open_store(&mut self, config: &WalletConfig) -> Result<Store, Error> {
		let data_dir_name = get_data_dir_name(config)?;
		Ok(Store::new(&data_dir_name, None, Some(DB_NAME), None)?)
	}

	pub fn update_state_info(
		&mut self,
		wallet_state_info: &mut WalletStateInfo,
		store: &Store,
	) -> Result<(), Error> {
		{
			let batch = store.batch()?;
			batch.put_ser(&WALLET_STATE_INFO_KEY, wallet_state_info)?;
			batch.commit()?;
		}

		Ok(())
	}

	fn build_context<'a, K: Keychain, N: NodeClient>(
		&self,
		keychain: &'a K,
		client: &'a N,
		config: &'a WalletConfig,
		wallet: &'a mut Wallet,
		wallet_state_info: &'a mut WalletStateInfo,
		store: &'a Store,
	) -> Result<Box<WalletContext<'a, K, N>>, Error> {
		let ctx = WalletContext::new(keychain, client, config, wallet, wallet_state_info, &store)?;

		Ok(Box::new(ctx))
	}

	fn get_keychain(&self, config: &WalletConfig, password: &str) -> Result<ExtKeychain, Error> {
		let data_file_dir = get_data_dir_name(config)?;
		let password = ZeroingString::from(password);
		let wallet_seed = WalletSeed::from_file(&data_file_dir, password)?;
		wallet_seed.derive_keychain(global::is_testnet())
	}

	fn get_mnemonic(&self, config: &WalletConfig, password: &str) -> Result<String, Error> {
		let data_file_dir = get_data_dir_name(config)?;
		let password = ZeroingString::from(password);
		let wallet_seed = WalletSeed::from_file(&data_file_dir, password)?;

		Ok(wallet_seed.to_mnemonic()?)
	}

	pub fn get_next_id(&mut self, store: &Store, account_id: u8) -> Result<u32, Error> {
		let batch = store.batch()?;
		let count: u32 = batch.get_ser(&[4u8, account_id])?.unwrap_or(0);
		Ok(count)
	}

	pub fn delete_txn(&mut self, id: u32, store: &Store, account_id: u8) -> Result<(), Error> {
		// load txs from db
		let iter = {
			let batch = store.batch()?;
			batch.iter(&[3u8, account_id], |_, v| {
				let txn_result: Result<TxEntry, ser::Error> =
					ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2)).map_err(From::from);
				Ok(txn_result)
			})
		};

		let mut tx_vec = vec![];
		for mut v in iter {
			loop {
				match v.next() {
					Some(tx_result) => {
						let tx_result = tx_result?;
						tx_vec.push(tx_result);
					}
					None => break,
				}
			}
		}

		for tx in tx_vec {
			if tx.id == id {
				let payment_id = tx.payment_id;
				let payment_id_as_slice = &format!("{}", payment_id);
				let mut tx_key = [3u8; PEDERSEN_COMMITMENT_SIZE + PAYMENT_ID_LEN + 3];
				tx_key[3..3 + PAYMENT_ID_LEN].clone_from_slice(payment_id_as_slice.as_bytes());
				tx_key[1] = account_id;
				tx_key[2] = match tx.tx_type {
					TxType::Sent => 0u8,
					TxType::Received => 1u8,
					TxType::Burn => 2u8,
					TxType::Claim => 3u8,
					TxType::Coinbase => 4u8,
					TxType::SentCancelled => 5u8,
					TxType::BurnCancelled => 6u8,
					TxType::ClaimCancelled => 7u8,
					TxType::PossibleReorg => 8u8,
				};
				match tx.output {
					Some(output) => {
						tx_key[3 + PAYMENT_ID_LEN..]
							.clone_from_slice(&output.identifier.commitment()[..]);
					}
					None => {
						tx_key[3 + PAYMENT_ID_LEN..]
							.clone_from_slice(&[0u8; PEDERSEN_COMMITMENT_SIZE]);
					}
				}

				{
					let batch = store.batch()?;
					let count: u32 = batch.get_ser(&[4u8, account_id])?.unwrap_or(0);
					batch.put_ser(&[4u8, account_id], &(count - 1))?;
					batch.delete(&tx_key)?;
					batch.commit()?;
				}
				return Ok(());
			}
		}

		Ok(())
	}

	pub fn cancel_txn(
		&mut self,
		tx: &mut TxEntry,
		id: u32,
		account_id: u8,
		store: &Store,
	) -> Result<(), Error> {
		let tx_type = match tx.tx_type {
			TxType::Sent => TxType::SentCancelled,
			TxType::Burn => TxType::BurnCancelled,
			TxType::Claim => TxType::ClaimCancelled,
			_ => {
				return Err(libwallet::ErrorKind::ImplsError(format!(
					"invalid transaction type for {}",
					id
				))
				.into());
			}
		};

		let payment_id_as_slice = &format!("{}", tx.payment_id);
		let mut tx_key = [3u8; PEDERSEN_COMMITMENT_SIZE + PAYMENT_ID_LEN + 3];
		tx_key[3..3 + PAYMENT_ID_LEN].clone_from_slice(payment_id_as_slice.as_bytes());
		tx_key[1] = account_id;
		tx_key[2] = match tx.tx_type {
			TxType::Sent => 0u8,
			TxType::Received => 1u8,
			TxType::Burn => 2u8,
			TxType::Claim => 3u8,
			TxType::Coinbase => 4u8,
			TxType::SentCancelled => 5u8,
			TxType::BurnCancelled => 6u8,
			TxType::ClaimCancelled => 7u8,
			TxType::PossibleReorg => 8u8,
		};
		match tx.output {
			Some(output) => {
				tx_key[3 + PAYMENT_ID_LEN..].clone_from_slice(&output.identifier.commitment()[..]);
			}
			None => {
				tx_key[3 + PAYMENT_ID_LEN..].clone_from_slice(&[0u8; PEDERSEN_COMMITMENT_SIZE]);
			}
		}

		let mut updated_tx_key = [3u8; PAYMENT_ID_LEN + 3];
		updated_tx_key[3..3 + PAYMENT_ID_LEN].clone_from_slice(payment_id_as_slice.as_bytes());
		updated_tx_key[1] = account_id;
		updated_tx_key[2] = match tx_type {
			TxType::Sent => 0u8,
			TxType::Received => 1u8,
			TxType::Burn => 2u8,
			TxType::Claim => 3u8,
			TxType::Coinbase => 4u8,
			TxType::SentCancelled => 5u8,
			TxType::BurnCancelled => 6u8,
			TxType::ClaimCancelled => 7u8,
			TxType::PossibleReorg => 8u8,
		};

		match tx.output {
			Some(output) => {
				updated_tx_key[3 + PAYMENT_ID_LEN..]
					.clone_from_slice(&output.identifier.commitment()[..]);
			}
			None => {
				updated_tx_key[3 + PAYMENT_ID_LEN..]
					.clone_from_slice(&[0u8; PEDERSEN_COMMITMENT_SIZE]);
			}
		}

		tx.tx_type = tx_type;

		{
			let batch = store.batch()?;
			batch.delete(&tx_key)?;
			batch.put_ser(&updated_tx_key, tx)?;
			batch.commit()?;
		}

		Ok(())
	}

	pub fn insert_txn(
		&mut self,
		tx: Option<Transaction>,
		output: Option<Output>,
		payment_id: PaymentId,
		_timestamp: u64,
		amount: u64,
		tx_type: TxType,
		id: u32,
		confirmation_block: u64,
		account_id: u8,
		store: &Store,
	) -> Result<(), Error> {
		// prefix the tx with '3u8'
		let payment_id_as_slice = &format!("{}", payment_id);
		let mut tx_key = [3u8; PEDERSEN_COMMITMENT_SIZE + PAYMENT_ID_LEN + 3];
		tx_key[3..3 + PAYMENT_ID_LEN].clone_from_slice(payment_id_as_slice.as_bytes());
		tx_key[1] = account_id;
		tx_key[2] = match tx_type {
			TxType::Sent => 0u8,
			TxType::Received => 1u8,
			TxType::Burn => 2u8,
			TxType::Claim => 3u8,
			TxType::Coinbase => 4u8,
			TxType::SentCancelled => 5u8,
			TxType::BurnCancelled => 6u8,
			TxType::ClaimCancelled => 7u8,
			TxType::PossibleReorg => 1u8, // reorgs for recevied
		};
		match output {
			Some(output) => {
				tx_key[3 + PAYMENT_ID_LEN..].clone_from_slice(&output.identifier.commitment()[..]);
			}
			None => {
				tx_key[3 + PAYMENT_ID_LEN..].clone_from_slice(&[0u8; PEDERSEN_COMMITMENT_SIZE]);
			}
		}

		let mut tx_key_cancelled_check = [3u8; PEDERSEN_COMMITMENT_SIZE + PAYMENT_ID_LEN + 3];
		if tx_type == TxType::Sent || tx_type == TxType::Burn || tx_type == TxType::Claim {
			tx_key_cancelled_check[3..3 + PAYMENT_ID_LEN]
				.clone_from_slice(payment_id_as_slice.as_bytes());
			tx_key_cancelled_check[1] = account_id;
			match tx_type {
				TxType::Sent => {
					tx_key_cancelled_check[2] = 5u8;
				}
				TxType::Burn => {
					tx_key_cancelled_check[2] = 6u8;
				}
				TxType::Claim => {
					tx_key_cancelled_check[2] = 7u8;
				}
				_ => { // can't happen
				}
			};
			match output {
				Some(output) => {
					tx_key[3 + PAYMENT_ID_LEN..]
						.clone_from_slice(&output.identifier.commitment()[..]);
				}
				None => {
					tx_key[3 + PAYMENT_ID_LEN..].clone_from_slice(&[0u8; PEDERSEN_COMMITMENT_SIZE]);
				}
			}
		}

		// check if this exists. If it does, use it's current ID
		let mut increment_tx_count = false;
		let id = {
			let batch = store.batch()?;
			let tx_holder: Option<TxEntry> = batch.get_ser(&tx_key)?;
			if tx_holder.is_some() {
				tx_holder.unwrap().id
			} else {
				increment_tx_count = true;
				id
			}
		};

		let tx_holder = TxEntry {
			id,
			tx_type: tx_type.clone(),
			amount,
			payment_id,
			confirmation_block,
			account_id,
			tx,
			output,
		};

		{
			let batch = store.batch()?;
			if increment_tx_count {
				// 4u8 prefix for counts
				let count: u32 = batch.get_ser(&[4u8, account_id])?.unwrap_or(0);
				batch.put_ser(&[4u8, account_id], &(count + 1))?;
			}
			batch.put_ser(&tx_key, &tx_holder)?;
			// delete the cancelled if it exists
			if tx_type == TxType::Sent || tx_type == TxType::Burn || tx_type == TxType::Claim {
				let entry: Option<TxEntry> = batch.get_ser(&tx_key_cancelled_check)?;
				if entry.is_some() {
					batch.delete(&tx_key_cancelled_check)?;
				}
			}
			batch.commit()?;
		}

		Ok(())
	}

	pub fn get_output_timestamp(
		&mut self,
		commit: Commitment,
		store: &Store,
	) -> Result<u64, Error> {
		// prefix the outputs with '1u8'
		let commit_as_slice = &commit[0..PEDERSEN_COMMITMENT_SIZE];
		let mut output_key = [1u8; PEDERSEN_COMMITMENT_SIZE + 1];
		output_key[1..].clone_from_slice(&commit_as_slice);

		{
			let batch = store.batch()?;
			let output_data: Option<OutputData> = batch.get_ser(&output_key)?;
			batch.commit()?;
			match output_data {
				Some(output_data) => Ok(output_data.timestamp),
				None => Ok(0),
			}
		}
	}

	pub fn insert_output(&mut self, output_data: OutputData, store: &Store) -> Result<(), Error> {
		// prefix the outputs with '1u8'
		let commit_as_slice = &output_data.output.identifier.commit[0..PEDERSEN_COMMITMENT_SIZE];
		let mut output_key = [1u8; PEDERSEN_COMMITMENT_SIZE + 1];
		output_key[1..].clone_from_slice(&commit_as_slice);

		{
			let batch = store.batch()?;
			batch.put_ser(&output_key, &output_data)?;
			batch.commit()?;
		}

		Ok(())
	}

	pub fn remove_outputs(
		&mut self,
		remove_list: Vec<OutputData>,
		store: &Store,
	) -> Result<(), Error> {
		{
			let batch = store.batch()?;

			for mut output_data in remove_list {
				// prefix the outputs with '1u8'
				let commit_as_slice =
					&output_data.output.identifier.commit[0..PEDERSEN_COMMITMENT_SIZE];
				let mut output_key = [1u8; PEDERSEN_COMMITMENT_SIZE + 1];
				output_key[1..].clone_from_slice(&commit_as_slice);
				output_data.output_type = OutputType::Spent;
				batch.put_ser(&output_key, &output_data)?;
			}
			batch.commit()?;
		}
		Ok(())
	}

	fn check_update_txns<N: NodeClient>(
		&mut self,
		client: &mut N,
		txns: Vec<TxEntry>,
		store: &Store,
	) -> Result<Vec<TxEntry>, Error> {
		let mut ret_vec = vec![];
		let mut req_vec = vec![];
		let mut tx_entry_vec = vec![];
		let mut tx_entry_confirmed = vec![];
		for tx_entry in txns {
			if tx_entry.confirmation_block == std::u64::MAX && tx_entry.tx.is_some() {
				let tx = tx_entry.tx.as_ref().unwrap();
				let kernel_excess = tx.kernels()[0].excess;
				req_vec.push(kernel_excess);
				tx_entry_vec.push(tx_entry);
			} else {
				tx_entry_confirmed.push(tx_entry);
			}
		}

		let res = client.get_kernels(req_vec)?;

		let mut count = 0;
		for height in res {
			let mut tx_entry = &mut tx_entry_vec[count];
			if height != u64::MAX {
				tx_entry.confirmation_block = height;
				let tx_type = if tx_entry.tx_type == TxType::SentCancelled {
					TxType::Sent
				} else if tx_entry.tx_type == TxType::BurnCancelled {
					TxType::Burn
				} else if tx_entry.tx_type == TxType::ClaimCancelled {
					TxType::Claim
				} else {
					tx_entry.tx_type.clone()
				};
				tx_entry.tx_type = tx_type.clone();

				self.insert_txn(
					tx_entry.tx.clone(),
					tx_entry.output.clone(),
					tx_entry.payment_id,
					0,
					tx_entry.amount,
					tx_type,
					tx_entry.id,
					height,
					tx_entry.account_id,
					&store,
				)?;
			}
			ret_vec.push(tx_entry.clone());

			count += 1;
		}

		for entry in tx_entry_confirmed {
			ret_vec.push(entry);
		}

		Ok(ret_vec)
	}

	fn lock_inputs(&mut self, inputs: Inputs, store: &Store, is_locked: bool) -> Result<(), Error> {
		{
			let batch = store.batch()?;
			for input in inputs {
				let commit_as_slice = &input.commit[0..PEDERSEN_COMMITMENT_SIZE];
				let mut output_key = [1u8; PEDERSEN_COMMITMENT_SIZE + 1];
				output_key[1..].clone_from_slice(&commit_as_slice);
				let output_data: Option<OutputData> = batch.get_ser(&output_key)?;
				if output_data.is_some() {
					let mut output_data = output_data.unwrap();
					output_data.is_locked = is_locked;
					batch.put_ser(&output_key, &output_data)?;
				}
			}
			batch.commit()?;
		}

		Ok(())
	}

	fn get_txns_from_db(&mut self, acct_index: u8, store: &Store) -> Result<Vec<TxEntry>, Error> {
		// load txs from db
		let iter = {
			let batch = store.batch()?;
			batch.iter(&[3u8, acct_index], |_, v| {
				let txn_result: Result<TxEntry, ser::Error> =
					ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2)).map_err(From::from);
				Ok(txn_result)
			})
		};

		let mut tx_vec = vec![];
		for mut v in iter {
			loop {
				match v.next() {
					Some(tx_result) => {
						let tx_result = tx_result?;
						if acct_index == tx_result.account_id {
							tx_vec.push(tx_result);
						}
					}
					None => break,
				}
			}
		}

		Ok(tx_vec)
	}

	pub fn delete_outputs_and_txs(
		&mut self,
		height: u64,
		store: &Store,
		account_id: u8,
		config: &WalletConfig,
	) -> Result<(), Error> {
		let mut client = HTTPNodeClient::new(&config.node, config.node_api_secret.clone());
		let outputs = self.get_outputs_from_db(SortType::HEIGHT, &store)?;

		let mut outputs_to_check = vec![];
		for output_data in outputs {
			if output_data.account_id == account_id && output_data.height > height {
				let commit_as_slice =
					&output_data.output.identifier.commit[0..PEDERSEN_COMMITMENT_SIZE];
				let mut output_key = [1u8; PEDERSEN_COMMITMENT_SIZE + 1];
				output_key[1..].clone_from_slice(&commit_as_slice);
				match output_data.output_type {
					OutputType::Spent => {
						outputs_to_check.push(output_data);
					}
					OutputType::PossibleReorg => {}
					_ => {
						let batch = store.batch()?;
						batch.delete(&output_key)?;
						batch.commit()?;
					}
				}
			}
		}

		let mut kernel_to_output_map = HashMap::new();
		let mut possible_reorgs = vec![];
		let txs = self.get_txns_from_db(account_id, &store)?;
		for output_data in &outputs_to_check {
			let mut found = false;
			for tx in &txs {
				if tx.confirmation_block != u64::MAX {
					match &tx.tx {
						Some(tx) => {
							for input in tx.inputs() {
								if input.commit == output_data.output.identifier.commitment() {
									kernel_to_output_map.insert(&tx.kernels()[0], output_data);
									found = true;
									break;
								}
							}
						}
						None => {}
					}
				}
			}

			if !found {
				possible_reorgs.push(output_data);
			}
		}

		let mut kernels = vec![];
		let mut excesses = vec![];

		for (k, _) in &kernel_to_output_map {
			excesses.push(k.excess);
			kernels.push(k);
		}

		let heights = client.get_kernels(excesses.clone())?;

		let mut count = 0;
		for height in heights {
			let kernel = kernels[count];
			if height == u64::MAX {
				// invalid kernel. We must take action
				possible_reorgs.push(kernel_to_output_map.get(kernel).unwrap().clone());
			}
			count += 1;
		}

		for output_data in possible_reorgs {
			let output_data = OutputData {
				output: output_data.output,
				payment_id: output_data.payment_id,
				mmr_index: output_data.mmr_index,
				timestamp: output_data.timestamp,
				value: output_data.value,
				height: output_data.height,
				lock_height: output_data.lock_height,
				is_coinbase: output_data.is_coinbase,
				account_id,
				output_type: OutputType::PossibleReorg,
				is_locked: false,
			};
			self.insert_output(output_data, &store)?;
		}

		// handle txns
		let iter = {
			let batch = store.batch()?;
			let iter = batch.iter(&[3u8, account_id], |_, v| {
				let txn_result: Result<TxEntry, ser::Error> =
					ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2)).map_err(From::from);
				Ok(txn_result)
			});
			iter
		};

		let mut tx_del_list = vec![];
		for mut v in iter {
			loop {
				match v.next() {
					Some(tx_result) => {
						let tx_result = tx_result?;
						if tx_result.confirmation_block > height {
							tx_del_list.push(tx_result);
						}
					}
					None => break,
				}
			}
		}

		let mut kernel_to_entry_map = HashMap::new();
		let mut unknown_list = vec![];
		for tx_entry in tx_del_list {
			match tx_entry.tx.clone() {
				Some(tx) => {
					// if we have the txn, add the kernel to our list
					kernel_to_entry_map.insert(tx.kernels()[0].clone(), tx_entry);
				}
				_ => {
					// if we don't have the txn, try the output and see
					// if it was the input to one of our txns
					// TODO: may improve performance by creating index in the db
					// probably needed for exchanges
					match tx_entry.output {
						Some(output) => {
							let mut found = false;
							for tx in &txs {
								if tx.confirmation_block != u64::MAX {
									match &tx.tx {
										Some(tx) => {
											for input in tx.inputs() {
												if input.commitment() == output.commitment() {
													kernel_to_entry_map.insert(
														tx.kernels()[0].clone(),
														tx_entry.clone(),
													);
													found = true;
												}
											}
										}
										None => {}
									}
								}
							}
							if !found {
								unknown_list.push(tx_entry);
							}
						}
						None => {
							unknown_list.push(tx_entry);
						} // can't continue
					}
				}
			}
		}

		let mut kernels = vec![];
		let mut excesses = vec![];

		for (k, _) in &kernel_to_entry_map {
			excesses.push(k.excess);
			kernels.push(k);
		}

		let heights = client.get_kernels(excesses.clone())?;

		let mut count = 0;
		for height in heights {
			let kernel = &kernels[count];
			if height == u64::MAX {
				// invalid kernel. We must take action
				unknown_list.push(kernel_to_entry_map.get(kernel).unwrap().clone());
			}
			count += 1;
		}

		for tx_entry in unknown_list {
			if tx_entry.tx_type == TxType::Received {
				self.insert_txn(
					tx_entry.tx,
					tx_entry.output,
					tx_entry.payment_id,
					SystemTime::now()
						.duration_since(UNIX_EPOCH)
						.unwrap()
						.as_millis() as u64,
					tx_entry.amount,
					TxType::PossibleReorg,
					tx_entry.id,
					std::u64::MAX,
					account_id,
					&store,
				)?;
			} else {
				self.insert_txn(
					tx_entry.tx,
					tx_entry.output,
					tx_entry.payment_id,
					SystemTime::now()
						.duration_since(UNIX_EPOCH)
						.unwrap()
						.as_millis() as u64,
					tx_entry.amount,
					tx_entry.tx_type,
					tx_entry.id,
					std::u64::MAX,
					account_id,
					&store,
				)?;
			}
		}

		Ok(())
	}

	fn get_outputs_from_db(
		&mut self,
		sort_type: SortType,
		store: &Store,
	) -> Result<Vec<OutputData>, Error> {
		// load outputs from db
		let batch = store.batch()?;
		let iter = batch.iter(&[1u8], |_, v| {
			let output_result: Result<OutputData, ser::Error> =
				ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2)).map_err(From::from);
			Ok(output_result)
		});

		let mut output_vec = vec![];
		for mut v in iter {
			loop {
				match v.next() {
					Some(output_result) => output_vec.push(output_result?),
					None => break,
				}
			}
		}

		match sort_type {
			SortType::VALUE => output_vec.sort_by_key(|x| x.value),
			SortType::HEIGHT => output_vec.sort_by_key(|x| x.height),
		}

		Ok(output_vec)
	}

	fn get_acct_index(&mut self, config: &WalletConfig, store: &Store) -> Result<(u8, u8), Error> {
		let mut max_index = 0;
		let mut ret_index = 0;
		let mut account_found = false;

		let iter = {
			let batch = store.batch()?;

			batch.iter(&[2u8], |_, v| {
				let account_result: Result<AccountInfo, ser::Error> =
					ser::deserialize(&mut v.clone(), ser::ProtocolVersion(2)).map_err(From::from);
				Ok(account_result)
			})
		};

		let mut account_vec = vec![];
		for mut v in iter {
			loop {
				match v.next() {
					Some(account_result) => account_vec.push(account_result?),
					None => break,
				}
			}
		}

		for account in account_vec {
			if account.index > max_index {
				max_index = account.index;
			}
			if account.name == config.account {
				ret_index = account.index;
				account_found = true;
			}
		}

		if config.account == "default" {
			ret_index = 0;
			account_found = true;
		}

		if account_found {
			Ok((ret_index, max_index))
		} else {
			Err(libwallet::error::ErrorKind::AccountError("Account not found".to_string()).into())
		}
	}

	fn select_coins_and_fee(
		&self,
		amount: u64,
		all_outputs: Vec<OutputData>,
		cur_height: u64,
		change_outputs: u32,
		selection_strategy_is_all: bool,
	) -> Result<(Vec<OutputData>, u64, Option<u64>), Error> {
		let eligible_outputs = all_outputs
			.iter()
			.filter(|out| out.lock_height <= cur_height)
			.collect::<Vec<&OutputData>>();

		let mut eligible_outputs = {
			let mut ret = vec![];
			for elig in eligible_outputs {
				if !elig.is_locked {
					ret.push(elig);
				}
			}
			ret
		};

		// keep going until we either run out of coins or have a successful transaction
		let mut selected_outputs = vec![];
		let mut total_value = 0;
		let change_outputs = change_outputs as usize;
		loop {
			match eligible_outputs.pop() {
				Some(next) => {
					total_value += next.value;
					selected_outputs.push(next.clone());
					let fee = tx_fee(selected_outputs.len(), 1, 1);
					if total_value == amount + fee && !selection_strategy_is_all {
						// no change outputs
						return Ok((selected_outputs, fee, None));
					} else if total_value > amount + fee && !selection_strategy_is_all {
						// take into consideration the change output
						let fee = tx_fee(selected_outputs.len(), 1 + change_outputs, 1);
						if total_value >= amount + fee {
							let change_amount = Some(total_value - (amount + fee));
							// note this could be 0. 0 commit's are o.k.
							return Ok((selected_outputs, fee, change_amount));
						}
						// otherwise, we continue in this loop
					}
				}
				None => {
					if selection_strategy_is_all {
						let fee_no_change = tx_fee(selected_outputs.len(), 1, 1);
						if amount + fee_no_change == total_value {
							// exact change worked with all
							return Ok((selected_outputs, fee_no_change, None));
						}
						let fee = tx_fee(selected_outputs.len(), 1 + change_outputs, 1);
						if amount + fee <= total_value {
							// we have enough to send with 'all'
							let change_amount = Some(total_value - (amount + fee));
							return Ok((selected_outputs, fee, change_amount));
						}
					}
					return Err(ErrorKind::InsufficientFunds(format!(
						"Total not enough, TODO: show needed amount"
					))
					.into());
				}
			}
		}
	}

	pub fn get_key_id(&self, account_id: u8) -> Identifier {
		ExtKeychain::derive_key_id(1, 1 + account_id as u32, 0, 0, 0)
	}

	pub fn build_send_transaction<K>(
		&mut self,
		keychain: &K,
		amount: u64,
		fee_u64: u64,
		outputs: Vec<OutputData>,
		recipient_address: Option<Address>,
		change_address: Address,
		change_amount: Option<u64>,
		change_outputs: u32,
		pri_view: SecretKey,
		payment_id: PaymentId,
		acct_index: u8,
		store: &Store,
	) -> Result<Transaction, Error>
	where
		K: Keychain,
	{
		let builder = ProofBuilder::new(keychain);
		let fee_u32: u32 = fee_u64.try_into()?;
		let mut elems = vec![];

		for output_data in outputs {
			elems.push(build::input(
				output_data.value,
				pri_view.clone(),
				output_data.output,
				output_data.mmr_index - 1,
			));
		}

		let is_burn;
		if recipient_address.is_some() {
			// add recipient output
			is_burn = false;
			let recipient_address = recipient_address.unwrap();
			let (private_nonce, _pub_nonce) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

			elems.push(build::output_wrnp(
				amount,
				private_nonce,
				recipient_address,
				payment_id,
			));
		} else {
			// it's a burn
			is_burn = true;
		}

		// add change output
		let pub_nonces = if change_amount.is_some() {
			let change_amount = change_amount.unwrap();
			let mut pub_nonces = vec![];

			for i in 0..change_outputs {
				let (private_nonce, pub_nonce) =
					keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
				let mut change_amount_i = change_amount / change_outputs as u64;
				if i == 0 {
					change_amount_i += change_amount % change_outputs as u64;
				}
				let change_output = build::output_wrnp(
					change_amount_i,
					private_nonce,
					change_address.clone(),
					payment_id,
				);
				elems.push(change_output);
				pub_nonces.push(pub_nonce);
			}
			Some(pub_nonces)
		} else {
			None
		};

		let tx = if !is_burn {
			build::transaction(
				KernelFeatures::Plain {
					fee: fee_u32.into(),
				},
				&elems[..],
				keychain,
				&builder,
			)
		} else {
			build::transaction(
				KernelFeatures::Burn {
					fee: fee_u32.into(),
					amount,
				},
				&elems[..],
				keychain,
				&builder,
			)
		}?;

		if change_amount.is_some() {
			// we have to figure out which one is the change output
			// by using rewind.

			let mut index_rewindable = vec![];
			let mut amount_lookup = HashMap::new();

			for pub_nonce in pub_nonces.unwrap() {
				let (ephemeral_key_q_r, _) = change_address
					.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &pub_nonce)
					.unwrap();

				let mut index = 0;
				loop {
					let output = tx.outputs()[index];
					let rewind = nit_rewind(
						keychain.secp(),
						&ProofBuilder::new(keychain),
						output.identifier.commit,
						ephemeral_key_q_r.clone(),
						None,
						output.proof,
					)?;

					match rewind {
						Some((amount, _message)) => {
							let change_amount = change_amount.unwrap();
							let change_outputs = change_outputs as u64;
							if amount == change_amount / change_outputs
								|| amount
									== change_amount / change_outputs
										+ change_amount % change_outputs
							{
								amount_lookup.insert(index, amount);
								index_rewindable.push(index);
							}
							break;
						}
						_ => {}
					}

					index += 1;
					if index >= tx.outputs().len() {
						break;
					}
				}
			}
			for index in index_rewindable {
				let change_amount_index = amount_lookup.get(&index).unwrap();
				let output_data = OutputData {
					output: tx.outputs()[index],
					payment_id,
					mmr_index: 0,
					timestamp: 0,
					value: *change_amount_index,
					height: 0,
					lock_height: 0,
					is_coinbase: false,
					account_id: acct_index,
					output_type: OutputType::ChangeZeroConf,
					is_locked: false,
				};
				self.insert_output(output_data, &store)?;
			}
		}

		Ok(tx)
	}

	fn get_local_address<K>(
		&self,
		account_id: u8,
		keychain: &K,
		config: &WalletConfig,
	) -> Result<Address, Error>
	where
		K: Keychain,
	{
		let key_id = self.get_key_id(account_id);
		let secret_key = keychain.derive_key(0, &key_id, SwitchCommitmentType::Regular)?;
		let pub_key = PublicKey::from_secret_key(&keychain.secp(), &secret_key)?;
		Ok(Address::from_one_pubkey(&pub_key, config.chain_type))
	}
}
