// Copyright 2019 The Grin Developers
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

//! Types and traits that should be provided by a wallet
//! implementation

use crate::error::Error;
use crate::grin_core::address::Address;
use crate::grin_core::core::{Output, Transaction, TxKernel};
use crate::grin_core::libtx::proof::PaymentId;
use crate::grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::grin_util::secp::pedersen;
use bmw_wallet_config::config::WalletConfig;
use std::collections::HashMap;

/// Encapsulate all wallet-node communication functions. No functions within libwallet
/// should care about communication details
pub trait NodeClient: Send + Sync + Clone {
	/// Return the URL of the check node
	fn node_url(&self) -> &str;

	/// Set the node URL
	fn set_node_url(&mut self, node_url: &str);

	/// Return the node api secret
	fn node_api_secret(&self) -> Option<String>;

	/// Change the API secret
	fn set_node_api_secret(&mut self, node_api_secret: Option<String>);

	/// Posts a transaction to a grin node
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), Error>;

	/// get status of a btc address for claims
	fn get_btc_address_status(&self, address: String) -> Result<(bool, bool, u64, u32), Error>;

	/// Returns the api version string and block header version as reported
	/// by the node. Result can be cached for later use
	fn get_version_info(&mut self) -> Option<NodeVersionInfo>;

	/// retrieves the current tip (height, hash) from the specified grin node
	fn get_chain_tip(&self) -> Result<(u64, String), Error>;

	/// Get kernel height of the block it's included in. Returns
	/// (Vec<height>)
	fn get_kernels(&mut self, excess: Vec<pedersen::Commitment>) -> Result<Vec<u64>, Error>;

	/// Get a kernel and the height of the block it's included in. Returns
	/// (tx_kernel, height, mmr_index)
	fn get_kernel(
		&mut self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error>;

	/// retrieve a list of outputs from the specified grin node
	/// need "by_height" and "by_id" variants
	fn get_outputs_from_node(
		&self,
		wallet_outputs: Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, Error>;

	/// Get a list of outputs from the node by traversing the UTXO
	/// set in PMMR index order.
	/// Returns
	/// (last available output index, last insertion index retrieved,
	/// outputs(commit, proof, is_coinbase, height, mmr_index))
	fn get_outputs_by_pmmr_index(
		&self,
		start_height: u64,
		end_height: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		Error,
	>;

	/// Get a list of outputs from the node by traversing the UTXO
	/// Returns only the outputs that the wallet has not yet seen based
	/// on specified sync_headers.
	/// Returns
	/// (
	///   (header_hash, height, mmr_index),
	///   (mmr_index, height, output(commit, proof, is_coinbase)),
	///    is_syncing
	/// )
	fn scan(
		&self,
		sync_headers: Vec<(String, u64, u64)>,
		max_count: u64,
		offset_mmr_index: u64,
		mmr_list: Vec<u64>,
	) -> Result<
		(
			Vec<(String, u64, u64)>,
			Vec<(u64, u64, Output)>,
			bool,
			Vec<u64>,
		),
		Error,
	>;

	/// Return the pmmr indices representing the outputs between a given
	/// set of block heights
	/// (start pmmr index, end pmmr index)
	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), Error>;
}

/// Node version info
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeVersionInfo {
	/// Semver version string
	pub node_version: String,
	/// block header verson
	pub block_header_version: u16,
	/// Whether this version info was successfully verified from a node
	pub verified: Option<bool>,
}

/// OutputType
#[derive(Debug, Clone, PartialEq)]
pub enum OutputType {
	Payment,
	Change,
	ChangeZeroConf,
	Coinbase,
	Spent,
	PossibleReorg,
}

/// OutputData holder for wallet
#[derive(Clone, Debug)]
pub struct OutputData {
	/// The actual output
	pub output: Output,
	/// The payment id for this output
	pub payment_id: PaymentId,
	/// timestamp of this output
	pub timestamp: u64,
	/// mmr_index of this output
	pub mmr_index: u64,
	/// value in nanobmws
	pub value: u64,
	/// height this output was confirmed at
	pub height: u64,
	/// height at which this output is spendable
	pub lock_height: u64,
	/// whether this output is a coinbase
	pub is_coinbase: bool,
	/// which account id is this output associated with
	pub account_id: u8,
	/// the output type
	pub output_type: OutputType,
	/// is the output locked,
	pub is_locked: bool,
}

impl Writeable for OutputData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.output.write(writer)?;
		self.payment_id.write(writer)?;
		writer.write_u64(self.timestamp)?;
		writer.write_u64(self.mmr_index)?;
		writer.write_u64(self.value)?;
		writer.write_u64(self.height)?;
		writer.write_u64(self.lock_height)?;
		writer.write_u8(if self.is_coinbase { 1 } else { 0 })?;
		writer.write_u8(self.account_id)?;
		match self.output_type {
			OutputType::Payment => writer.write_u8(1)?,
			OutputType::Change => writer.write_u8(2)?,
			OutputType::ChangeZeroConf => writer.write_u8(3)?,
			OutputType::Coinbase => writer.write_u8(4)?,
			OutputType::Spent => writer.write_u8(5)?,
			OutputType::PossibleReorg => writer.write_u8(6)?,
		}
		match self.is_locked {
			false => writer.write_u8(0)?,
			true => writer.write_u8(1)?,
		}
		Ok(())
	}
}

impl Readable for OutputData {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let output = Output::read(reader)?;
		let payment_id = PaymentId::read(reader)?;
		let timestamp = reader.read_u64()?;
		let mmr_index = reader.read_u64()?;
		let value = reader.read_u64()?;
		let height = reader.read_u64()?;
		let lock_height = reader.read_u64()?;
		let is_coinbase = reader.read_u8()? != 0;
		let account_id = reader.read_u8()?;
		let output_type = match reader.read_u8() {
			Ok(1) => OutputType::Payment,
			Ok(2) => OutputType::Change,
			Ok(3) => OutputType::ChangeZeroConf,
			Ok(4) => OutputType::Coinbase,
			Ok(5) => OutputType::Spent,
			Ok(6) => OutputType::PossibleReorg,
			_ => return Err(ser::Error::CorruptedData),
		};
		let is_locked = match reader.read_u8()? {
			0 => false,
			_ => true,
		};

		Ok(OutputData {
			output,
			payment_id,
			timestamp,
			mmr_index,
			value,
			height,
			lock_height,
			is_coinbase,
			account_id,
			output_type,
			is_locked,
		})
	}
}

pub trait InitResponse {
	fn get_mnemonic(&self) -> Result<String, Error>;
}

pub trait InfoResponse {
	fn get_height(&self) -> Result<u64, Error>;
	fn get_balance(&self) -> Result<f64, Error>;
	fn get_spendable(&self) -> Result<f64, Error>;
	fn get_output_count(&self) -> Result<u64, Error>;
}

pub trait OutputsResponse {
	fn get_outputs_data(&self) -> Result<Vec<OutputData>, Error>;
	fn get_height(&self) -> Result<u64, Error>;
}

pub trait AddressResponse {
	fn get_address(&self) -> Result<Address, Error>;
}

pub trait SendResponse {
	fn get_payment_id(&self) -> Result<PaymentId, Error>;
}

pub trait BurnResponse {
	fn get_payment_id(&self) -> Result<PaymentId, Error>;
}

pub trait BackupResponse {
	fn get_backup_response(&self) -> Result<String, Error>;
}

pub trait TxsResponse {
	fn tx_entries(&self) -> Result<Vec<TxEntry>, Error>;
	fn get_height(&self) -> Result<u64, Error>;
	fn get_timestamps(&self) -> Result<Vec<u64>, Error>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum TxType {
	Sent,
	Received,
	Burn,
	Claim,
	Coinbase,
	SentCancelled,
	BurnCancelled,
	ClaimCancelled,
	PossibleReorg,
}

impl std::fmt::Display for TxType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TxType::Sent => write!(f, "Sent"),
			TxType::Received => write!(f, "Received"),
			TxType::Burn => write!(f, "Burn"),
			TxType::Claim => write!(f, "Claim"),
			TxType::Coinbase => write!(f, "Coinbase"),
			TxType::SentCancelled => write!(f, "Sent (Cancelled)"),
			TxType::BurnCancelled => write!(f, "Burn (Cancelled)"),
			TxType::ClaimCancelled => write!(f, "Claim (Cancelled)"),
			TxType::PossibleReorg => write!(f, "Possible Reorg TX"),
		}
	}
}

impl Readable for TxType {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(match reader.read_u8()? {
			0u8 => TxType::Sent,
			1u8 => TxType::Received,
			2u8 => TxType::Burn,
			3u8 => TxType::Claim,
			4u8 => TxType::Coinbase,
			5u8 => TxType::SentCancelled,
			6u8 => TxType::BurnCancelled,
			7u8 => TxType::ClaimCancelled,
			8u8 => TxType::PossibleReorg,
			_ => return Err(ser::Error::CorruptedData),
		})
	}
}

impl Writeable for TxType {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(match self {
			TxType::Sent => 0u8,
			TxType::Received => 1u8,
			TxType::Burn => 2u8,
			TxType::Claim => 3u8,
			TxType::Coinbase => 4u8,
			TxType::SentCancelled => 5u8,
			TxType::BurnCancelled => 6u8,
			TxType::ClaimCancelled => 7u8,
			TxType::PossibleReorg => 8u8,
		})?;

		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct TxEntry {
	pub id: u32,
	pub tx_type: TxType,
	pub amount: u64,
	pub payment_id: PaymentId,
	pub confirmation_block: u64,
	pub account_id: u8,
	pub tx: Option<Transaction>,
	pub output: Option<Output>,
}

impl Readable for TxEntry {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let id = reader.read_u32()?;
		let tx_type = TxType::read(reader)?;
		let amount = reader.read_u64()?;
		let payment_id = PaymentId::read(reader)?;
		let confirmation_block = reader.read_u64()?;
		let account_id = reader.read_u8()?;
		let tx = match reader.read_u8()? {
			1 => Some(Transaction::read(reader)?),
			_ => None,
		};
		let output = match reader.read_u8()? {
			1 => Some(Output::read(reader)?),
			_ => None,
		};

		Ok(TxEntry {
			id,
			tx_type,
			amount,
			payment_id,
			confirmation_block,
			account_id,
			tx,
			output,
		})
	}
}

impl Writeable for TxEntry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.id)?;
		self.tx_type.write(writer)?;
		writer.write_u64(self.amount)?;
		self.payment_id.write(writer)?;
		writer.write_u64(self.confirmation_block)?;
		writer.write_u8(self.account_id)?;
		if self.tx.is_some() {
			let tx = self.tx.as_ref().unwrap();
			writer.write_u8(1)?;
			tx.write(writer)?;
		} else {
			writer.write_u8(0)?;
		}

		if self.output.is_some() {
			let output = self.output.as_ref().unwrap();
			writer.write_u8(1)?;
			output.write(writer)?;
		} else {
			writer.write_u8(0)?;
		}

		Ok(())
	}
}

pub trait AccountResponse {
	fn created(&self) -> Result<&Option<AccountInfo>, Error>;
	fn accounts(&self) -> Result<&Vec<AccountInfo>, Error>;
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
	pub index: u8,
	pub name: String,
}

impl Writeable for AccountInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.index)?;
		writer.write_u8(self.name.len() as u8)?;
		writer.write_fixed_bytes(self.name.as_bytes())?;

		Ok(())
	}
}

impl Readable for AccountInfo {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let index = reader.read_u8()?;
		let len = reader.read_u8()?;
		let name = std::str::from_utf8(&reader.read_fixed_bytes(len.into())?)?.to_string();

		Ok(AccountInfo { name, index })
	}
}

pub trait WalletInst {
	fn init(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn InitResponse>, Error>;

	fn info(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn InfoResponse>, Error>;

	fn outputs(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn OutputsResponse>, Error>;

	fn address(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn AddressResponse>, Error>;

	fn account(
		&mut self,
		config: &WalletConfig,
		pass: &str,
	) -> Result<Box<dyn AccountResponse>, Error>;

	fn cancel(&mut self, config: &WalletConfig, password: &str) -> Result<(), Error>;

	fn send(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn SendResponse>, Error>;

	fn burn(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn BurnResponse>, Error>;

	fn backup(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<dyn BackupResponse>, Error>;

	fn gen_challenge(
		&mut self,
		config: &WalletConfig,
		password: &str,
	) -> Result<Box<String>, Error>;

	fn claim_bmw(
		&mut self,
		config: &WalletConfig,
		challenge: String,
		signatures: Vec<String>,
		redeem_script: Option<String>,
		address_type: u8,
		password: &str,
	) -> Result<(), Error>;

	fn txs(&mut self, config: &WalletConfig, pass: &str) -> Result<Box<dyn TxsResponse>, Error>;
}
