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
	inner: Context<ErrorKind>,
}

#[derive(Debug, Fail)]
/// Wallet config error types
pub enum ErrorKind {
	/// Seed Error
	#[fail(display = "Seed Error occurred: {}", _0)]
	SeedError(String),
	/// SyncingError
	#[fail(display = "Node is still syncing. Please wait: {}", _0)]
	SyncingError(String),
	/// Internal Error
	#[fail(display = "Internal Error occurred: {}", _0)]
	InternalError(String),
	/// Illegal Argument
	#[fail(display = "Illegal Argument Error: {}", _0)]
	IllegalArgument(String),
	/// Config Error
	#[fail(display = "Config Error occurred: {}", _0)]
	Config(String),
	/// Encryption Error
	#[fail(display = "Password mismatch")]
	Encryption,
	/// Generic Error
	#[fail(display = "Generic Error: {}", _0)]
	GenericError(String),
	/// TryInto Error
	#[fail(display = "TryInto Error: {}", _0)]
	TryInto(String),
	/// Insufficient Funds
	#[fail(display = "Insufficient Funds: {}", _0)]
	InsufficientFunds(String),
	/// Keychain Error
	#[fail(display = "Keychain Error: {}", _0)]
	Keychain(String),
	/// Mnemonic Error
	#[fail(display = "Mnemonic Error")]
	Mnemonic,
	/// Path not found error
	#[fail(display = "Path not found: {}", _0)]
	PathNotFoundError(String),
	/// IO Error
	#[fail(display = "IO Error")]
	IO,
	/// Wallet Seed Doesn't Exist Error
	#[fail(display = "Wallet Seed doesn't exist")]
	WalletSeedDoesntExist,
	/// Format Error
	#[fail(display = "Format Error")]
	Format,
	/// Store Error
	#[fail(display = "Store Error: {}", _0)]
	StoreError(String),
	/// LibWallet Error
	#[fail(display = "LibWallet Error: {}", _0)]
	LibWallet(String),
	/// Wallet seed doesn't exist
	#[fail(display = "Wallet doesn't exist at {}. {}", _0, _1)]
	WalletDoesntExist(String, String),
	/// Wallet Seeds Exists
	#[fail(display = "Wallet Seed Exists: {}", _0)]
	WalletSeedExists(String),
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

impl From<bmw_wallet_util::grin_keychain::Error> for Error {
	fn from(error: bmw_wallet_util::grin_keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(format!("{}", error))),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::PathNotFoundError(format!("{}", error))),
		}
	}
}

impl From<Error> for bmw_wallet_libwallet::error::Error {
	fn from(error: Error) -> bmw_wallet_libwallet::error::Error {
		bmw_wallet_libwallet::error::Error {
			inner: Context::new(bmw_wallet_libwallet::error::ErrorKind::ImplsError(format!(
				"{}",
				error
			))),
		}
	}
}

impl From<bmw_wallet_util::grin_store::Error> for Error {
	fn from(error: bmw_wallet_util::grin_store::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::StoreError(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_libwallet::error::Error> for Error {
	fn from(error: bmw_wallet_libwallet::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibWallet(format!("{}", error))),
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

impl From<std::num::TryFromIntError> for Error {
	fn from(error: std::num::TryFromIntError) -> Error {
		Error {
			inner: Context::new(ErrorKind::TryInto(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_libwallet::ErrorKind> for Error {
	fn from(error: bmw_wallet_libwallet::ErrorKind) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("Libwallet: {}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::libtx::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("Libtx: {}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_util::secp::Error> for Error {
	fn from(error: bmw_wallet_util::grin_util::secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("secp: {}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::ser::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("ser error: {}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::address::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::address::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!(
				"address error: {}",
				error
			))),
		}
	}
}
