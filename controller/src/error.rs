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
/// Wallet controller error types
pub enum ErrorKind {
	/// Impls Error
	#[fail(display = "Impls Error occurred: {}", _0)]
	ImplsError(String),
	/// LibWallet Error
	#[fail(display = "Libwallet Error occurred: {}", _0)]
	LibWallet(String),
	/// IO Error
	#[fail(display = "IO Error occurred: {}", _0)]
	IO(String),
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

impl From<bmw_wallet_libwallet::error::Error> for Error {
	fn from(error: bmw_wallet_libwallet::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibWallet(format!("{}", error))),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IO(format!("{}", error))),
		}
	}
}
