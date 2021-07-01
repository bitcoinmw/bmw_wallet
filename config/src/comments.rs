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

use crate::conf_util::get_top_level_dir_name;
use crate::config::WalletConfig;
use crate::error::Error;
use crate::error::ErrorKind;
use bmw_wallet_util::grin_core::global::ChainTypes;
use std::fs::File;
use std::io::Write;

/// This is hte default TOML file. It's modified based on user input.
const DEFAULT_TOML: &str = "\
\n\
#########################################\n\
### WALLET CONFIGURATION              ###\n\
#########################################\n\
[wallet]\n\
\n\
chain_type = \"REPLACE_NETWORK\"\n\
\n\
# Full Node\n\
node = \"REPLACE_NODE\"\n\
\n\
#location of the node api secret for basic auth on the BMW node API\n\
node_api_secret_path = \"REPLACE_ROOT_DIR/.foreign_api_secret\"\n\
\n\
";

/// This function builds the toml file based on the WalletConfig argument
/// The toml file is saved in the specified location
pub fn build_toml(toml_location: String, config: &WalletConfig) -> Result<(), Error> {
	let file = File::create(toml_location.clone());
	// make sure we can create the file.
	match file {
		Ok(mut file) => {
			// replace all parameters
			let toml = DEFAULT_TOML
				.replace("REPLACE_NETWORK", &config.chain_type.longname())
				.replace(
					"REPLACE_NODE",
					match &config.chain_type {
						ChainTypes::Mainnet => "http://127.0.0.1:3413",
						_ => "http://127.0.0.1:13413",
					},
				)
				.replace("REPLACE_ROOT_DIR", &get_top_level_dir_name(&config)?);

			// write file
			file.write_all(toml.as_bytes())?;

			Ok(())
		}
		Err(_) => Err(ErrorKind::PathNotFoundError(format!(
			"directory: {} doesn't exist. Perhaps create it first.",
			toml_location
		))
		.into()),
	}
}
