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

use core::num::ParseFloatError;
use core::num::ParseIntError;
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
	/// Config not found error
	#[fail(display = "Config not found")]
	ConfigNotFound,
	/// Path Not Found
	#[fail(display = "Path Not Found: {}", _0)]
	PathNotFoundError(String),
	/// Internal Error
	#[fail(display = "Internal Error: {}", _0)]
	InternalError(String),
	/// Toml Error
	#[fail(display = "Toml Error: {}", _0)]
	TomlError(String),
	/// Parse Error
	#[fail(display = "Parse Error: {}", _0)]
	Parse(String),
	/// Invalid Address Error
	#[fail(display = "Invalid Address Error: {}", _0)]
	InvalidAddress(String),
	/// Invalid address type
	#[fail(display = "Invalid Address Type: {}", _0)]
	InvalidAddressType(String),
	/// Argument not found
	#[fail(display = "Required argument not found: {}", _0)]
	ArgumentNotFound(String),
	/// Invalid Argument
	#[fail(display = "Invalid Argument: {}", _0)]
	InvalidArgument(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl From<failure::Context<ErrorKind>> for Error {
	fn from(e: failure::Context<ErrorKind>) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(e.to_string())),
		}
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
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

impl From<toml::de::Error> for Error {
	fn from(error: toml::de::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::TomlError(format!("{}", error))),
		}
	}
}

impl From<ParseFloatError> for Error {
	fn from(error: ParseFloatError) -> Error {
		Error {
			inner: Context::new(ErrorKind::Parse(format!("{}", error))),
		}
	}
}

impl From<bmw_wallet_util::grin_core::address::Error> for Error {
	fn from(error: bmw_wallet_util::grin_core::address::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InvalidAddress(format!("{}", error))),
		}
	}
}

impl From<ParseIntError> for Error {
	fn from(error: ParseIntError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InvalidAddressType(format!("{}", error))),
		}
	}
}
