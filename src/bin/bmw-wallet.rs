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

extern crate clap;
extern crate log;

use bmw_wallet_config::config::get_config;
use bmw_wallet_controller::controller::run_command;
use bmw_wallet_impls::wallet::Wallet;
use bmw_wallet_util::grin_core::global;
use bmw_wallet_util::grin_util::init_logger;
use failure::{Context, Fail};
use std::fmt;
use std::fmt::Display;

fn main() -> Result<(), Error> {
	// init logging
	init_logger(None, None);

	// obtain config
	let config = get_config()?;

	// set chaintype here
	global::init_global_chain_type(config.chain_type);

	let mut wallet = Wallet::new()?;

	// pass control to the controller
	run_command(config, &mut wallet)?;

	Ok(())
}

#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Debug, Fail)]
/// Wallet config error types
pub enum ErrorKind {
	/// Config not found error
	#[fail(display = "Config Error: {}", _0)]
	ConfigError(String),
	/// Impls Error
	#[fail(display = "Impls Error: {}", _0)]
	ImplsError(String),
	/// Controller Error
	#[fail(display = "Controller Error: {}", _0)]
	Controller(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl From<bmw_wallet_config::error::Error> for Error {
	fn from(e: bmw_wallet_config::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::ConfigError(format!("{}", e))),
		}
	}
}

impl From<bmw_wallet_impls::error::Error> for Error {
	fn from(e: bmw_wallet_impls::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::ImplsError(format!("{}", e))),
		}
	}
}

impl From<bmw_wallet_controller::error::Error> for Error {
	fn from(e: bmw_wallet_controller::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Controller(format!("{}", e))),
		}
	}
}
