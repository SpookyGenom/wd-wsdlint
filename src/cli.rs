use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Prune Workday WSDL and inject WS-Policy UsernameToken"
)]
pub struct CliOps {
    /// Path to Workday WSDL file
    #[arg(short = 'i', long, value_name = "FILE")]
    pub wsdl: String,

    /// Path to output pruned WSDL file
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: String,

    /// Path to configuration JSON file
    #[arg(
        short = 'c',
        long,
        value_name = "FILE",
        default_value = "config.dist.json"
    )]
    pub config: String,

    /// Service key in configuration JSON
    #[arg(short = 's', long, value_name = "SERVICE")]
    pub service: String,

    /// Policy XML file to inject if binding SOAP has no policy
    #[arg(long)]
    pub policy: Option<String>,
}
