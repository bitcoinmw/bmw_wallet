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

use crate::config::WalletConfig;
use crate::error::Error;
use crate::error::ErrorKind;
use dirs;
use std::fs;
use std::path::PathBuf;

const BMW_HOME: &str = ".bmw";

/// Convenience function to get the top level directory name
pub fn get_top_level_dir_name(config: &WalletConfig) -> Result<String, Error> {
	let mut bmw_path = PathBuf::new();
	Ok(if config.current_dir.is_some() {
		config
			.current_dir
			.clone()
			.unwrap()
			.into_os_string()
			.into_string()
			.unwrap()
	} else {
		get_bmw_path(
			&config.chain_type.shortname(),
			config.create_path,
			&mut bmw_path,
		)?;
		(&bmw_path).clone().into_os_string().into_string().unwrap()
	})
}

/// Get the data directory based on the specified config object
pub fn get_data_dir_name(config: &WalletConfig) -> Result<String, Error> {
	let data_dir_name = get_top_level_dir_name(config)?;
	Ok(format!("{}/wallet_data", data_dir_name))
}

/// Get the bmw path
pub fn get_bmw_path(
	short_name: &str,
	create_path: bool,
	bmw_path: &mut PathBuf,
) -> Result<(), Error> {
	// Check if bmw dir exists

	match dirs::home_dir() {
		Some(p) => {
			let home_dir_str = p.into_os_string().into_string().unwrap();
			bmw_path.push(home_dir_str);
			bmw_path.push(BMW_HOME);
		}

		_ => {}
	}

	bmw_path.push(short_name);

	// Create if the default path doesn't exist
	if !bmw_path.exists() && create_path {
		fs::create_dir_all(bmw_path.clone())?;
	}

	if !bmw_path.exists() {
		Err(ErrorKind::PathNotFoundError(String::from(bmw_path.to_str().unwrap())).into())
	} else {
		Ok(())
	}
}
