use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Args {
    #[structopt(subcommand)]
    pub mode: Mode,
}

#[derive(StructOpt, Debug)]
pub enum Mode {
    Server {
        #[structopt(short, long, default_value = "[::0]:2222")]
        listen: String,
        #[structopt(long, default_value = "localhost")]
        auto_generate: String,
        #[structopt(long, default_value)]
        cert: Cert,
        #[structopt(long, default_value)]
        key: Key,
        #[structopt(long, default_value)]
        root_cert: RootCert,
        #[structopt(long, default_value)]
        root_key: RootKey,
        #[structopt(long, default_value)]
        client_cert: ClientCert,
        #[structopt(long, default_value)]
        client_key: ClientKey,
        #[structopt(long)]
        no_client_auth: bool,
        #[structopt(long, default_value = "300")]
        conn_timeout: u64,
        #[structopt(long, default_value = "^.*$")]
        target_whitelist: String,
    },
    NC {
        #[structopt(long, default_value)]
        client_cert: ClientCert,
        #[structopt(long, default_value)]
        client_key: ClientKey,
        #[structopt(long)]
        no_client_auth: bool,
        #[structopt(long, default_value = "10")]
        keep_alive: u64,
        #[structopt(long, default_value = "300")]
        conn_timeout: u64,

        endpoint: String,
        target: String,
    },
    Client {
        #[structopt(long, default_value)]
        client_cert: ClientCert,
        #[structopt(long, default_value)]
        client_key: ClientKey,
        #[structopt(long)]
        no_client_auth: bool,
        #[structopt(long, default_value = "10")]
        keep_alive: u64,
        #[structopt(long, default_value = "300")]
        conn_timeout: u64,

        endpoint: String,
        target: String,
    },
}

#[derive(StructOpt, Clone, Debug)]
pub struct Cert {
    pub str: String,
}
impl Default for Cert {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        Cert {
            str: String::from(proj_dirs.config_dir().join("server.crt").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for Cert {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Cert {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
pub struct Key {
    pub str: String,
}
impl Default for Key {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        Key {
            str: String::from(proj_dirs.config_dir().join("server.key").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for Key {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Key {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
pub struct RootKey {
    pub str: String,
}
impl Default for RootKey {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        RootKey {
            str: String::from(proj_dirs.config_dir().join("root.key").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for RootKey {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RootKey {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
pub struct RootCert {
    pub str: String,
}
impl Default for RootCert {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        RootCert {
            str: String::from(proj_dirs.config_dir().join("root.crt").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for RootCert {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RootCert {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for RootCert {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
pub struct ClientKey {
    pub str: String,
}
impl Default for ClientKey {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        ClientKey {
            str: String::from(proj_dirs.config_dir().join("client.key").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for ClientKey {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ClientKey {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
pub struct ClientCert {
    pub str: String,
}
impl Default for ClientCert {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        ClientCert {
            str: String::from(proj_dirs.config_dir().join("client.crt").to_str().unwrap()),
        }
    }
}
impl std::str::FromStr for ClientCert {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ClientCert {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for ClientCert {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}
