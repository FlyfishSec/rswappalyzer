# rswappalyzer 🚀

A high-performance Wappalyzer rule detection Library.

极速 ***wappalyzer*** 规则检测库

---

## Installation 📦 | 安装

Add this to your `Cargo.toml`:

```cmd
cargo add rswappalyzer
```

## Quick Start⚡| 快速开始

Below is a minimal example demonstrating how to detect web technologies
from an HTTP response using **rswappalyzer**.

```rust
use reqwest::Client;
use reqwest::header::HeaderMap;
use rswappalyzer::{RuleConfig, TechDetector};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Build rule configuration
    // Use default configuration (recommended for most users)
    let config = RuleConfig::default();

    // load rules from a local file
    // let mut config = RuleConfig::default();
    // config.origin = RuleOrigin::LocalFile("/path/to/rules.json".to_string());

    // ---------------------------------------------------------------------
    // Remote rule configuration (optional)
    // ---------------------------------------------------------------------

    // Remote rule source
    // This example uses the official WappalyzerGo fingerprint dataset
    // as a standardized, community-maintained rule source.
    //
    // NOTE:
    // - Remote rules will be downloaded and cached locally
    // - Suitable for keeping rules up-to-date without bundling them into the binary
    //
    // const RULE_REMOTE_URL: &str =
    //     "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json";
    //
    // let mut config = RuleConfig::remote_custom(
    //     RULE_REMOTE_URL,             // Remote rule URL
    //     Duration::from_secs(10),     // HTTP request timeout
    //     RetryPolicy::Times(2),       // Retry policy (retry up to 2 times on failure)
    // );

    // ---------------------------------------------------------------------
    // Optional configuration overrides
    // ---------------------------------------------------------------------
    // Disable remote rule update checks
    // Useful for fully offline or deterministic environments
    // config.options.check_update = false;
    
    // Specify a custom cache directory for downloaded rules
    // Defaults to the library-managed cache location
    // config.options.cache_dir = PathBuf::from("./custom_cache");

    // 2. Create a technology detector instance
    // The detector owns all compiled rule data and is safe to reuse
    // across multiple requests.
    let detector = TechDetector::new(config).await?;

    // 3. Send HTTP request
    let client = Client::new();
    let url = "https://example.com";
    let response = client.get(url).send().await?;

    // 4. Extract headers and response body
    let headers: HeaderMap = response.headers().clone();
    let body = response.bytes().await?;

    // 5. Run technology detection
    let result = detector.detect(&headers, &[url], body.as_ref())?;

    // 6. Consume detection results
    // Get detected technology names
    println!("Technologies: {:?}", result.tech_list());

    // Get full structured result as pretty-printed JSON
    println!("{}", result.to_json_pretty()?);

    Ok(())
}
```

Example Output:

Detected technologies:

```text
["Cloudflare"]
```

Full detection result (JSON):

```json
{
  "technologies": [
    {
      "name": "Cloudflare",
      "categories": ["CDN"],
      "confidence": 85
    }
  ]
}
```

## Performance ⚡ | 性能

- **Throughput:** ~2,089 QPS (Windows, 4 cores)
- **Avg Latency:** ~0.47 ms
- **Concurrency:** 256 (Tokio async)
- **Build:** release

```bash
cargo run --release --example benchmark_detect_concurrent
```

## Enjoy it! 🚀

Happy hacking with rswappalyzer!

## Data Sources 📚 | 规则源

The following projects are used as rule sources:

- **WebAppAnalyzergo**  
<https://github.com/projectdiscovery/wappalyzergo>

- **WebAppAnalyzer**  
  <https://github.com/enthec/webappanalyzer>

- **Wappalyzer (HTTPArchive)**  
  <https://github.com/HTTPArchive/wappalyzer>

## References 🧩 | 参考项目

- **RustedWappalyzer**  
  <https://github.com/shart123456/RustedWappalyzer>

- **wappalyzergo**  
  <https://github.com/projectdiscovery/wappalyzergo>

---

## License 📄 | 许可证

This project is licensed under the MIT License.  
本项目基于 **MIT 许可证** 开源。
