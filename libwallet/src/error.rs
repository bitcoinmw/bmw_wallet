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

use failure::{Context, Fail};
use std::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub struct Error {
	pub inner: Context<ErrorKind>,
}

#[derive(Debug, Fail)]
/// Wallet config error types
pub enum ErrorKind {
	/// Impls Error
	#[fail(display = "Impls Error: {}", _0)]
	ImplsError(String),
	/// BTCSignatureInvalid
	#[fail(display = "Invalid BTC Signature")]
	BTCSignatureInvalid,
	/// Illegal Argument
	#[fail(display = "Illegal Arguent Error: {}", _0)]
	IllegalArgument(String),
	/// OsString error
	#[fail(display = "OsString Error: {}", _0)]
	OsString(String),
	/// Internal Error
	#[fail(display = "Internal Error: {}", _0)]
	InternalError(String),
	/// Account Error
	#[fail(display = "Account Error: {}", _0)]
	AccountError(String),
	/// No signatures were specified
	#[fail(display = "No signatures specified")]
	NoSignatures,
	/// store error
	#[fail(display = "Store Error: {}", _0)]
	StoreError(String),
	/// config error
	#[fail(display = "Config Error: {}", _0)]
	Config(String),
	/// Client Callback Error
	#[fail(display = "Client Callback Error: {}", _0)]
	ClientCallback(String),
	/// RPC Comms error
	#[fail(display = "RPC Communication Error")]
	RPCCommunicationError(String),
	/// Secp Error
	#[fail(display = "Secp Error: {}", _0)]
	SecpError(String),
	/// Keychain Error
	#[fail(display = "Keychain Error: {}", _0)]
	KeychainError(String),
	/// Ser Error
	#[fail(display = "Ser Error: {}", _0)]
	SerError(String),
	/// Transaction Error
	#[fail(display = "Transaction Error: {}", _0)]
	TransactionError(String),
	/// Internal Error
	#[fail(display = "Internal Error: {}", _0)]
	Internal(String),
	#[fail(display = "BTC Address Already Claimed")]
	BTCAddressAlreadyClaimed,
	#[fail(display = "BTC Address Invalid")]
	BTCAddressInvalid,
	#[fail(display = "Redeem Script is Invalid")]
	InvalidRedeemScript,
	#[fail(display = "Redeem Script non standard (len > 520)")]
	RedeemScriptNonStandard,
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<bmw_wallet_util::grin_store::Error> for Error {
	fn from(error: bmw_wallet_util::grin_store::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::StoreError(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_config::error::Error> for Error {
	fn from(error: bmw_wallet_config::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Config(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_util::secp::Error> for Error {
	fn from(error: bmw_wallet_util::grin_util::secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::SecpError(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_keychain::Error> for Error {
	fn from(error: bmw_wallet_util::grin_keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::KeychainError(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::ser::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::SerError(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::core::transaction::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::core::transaction::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::TransactionError(format!("{}", error))),
		}
	}
}

impl From<std::num::TryFromIntError> for Error {
	fn from(error: std::num::TryFromIntError) -> Error {
		Error {
			inner: Context::new(ErrorKind::Internal(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::libtx::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Internal(format!("{}", error))),
		}
	}
}

impl From<bitcoin::secp256k1::Error> for Error {
	fn from(error: bitcoin::secp256k1::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Internal(format!("{}", error))),
		}
	}
}
