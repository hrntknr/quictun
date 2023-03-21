#[derive(Debug)]
pub struct PortAddress {
    pub port: u16,
    pub address: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError;

impl std::str::FromStr for PortAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let idx = s.find(':');
        if idx.is_none() {
            return Err(ParseError);
        }
        let (port, address) = s.split_at(idx.unwrap());
        let port = match port
            .parse::<u16>()
            .map_err(|e| format!("Invalid port: {}", e))
        {
            Ok(0) => return Err(ParseError),
            Ok(v) => v,
            Err(_) => return Err(ParseError),
        };
        Ok(Self {
            port,
            address: address[1..].to_string(),
        })
    }
}
