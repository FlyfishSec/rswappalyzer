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
use rswappalyzer::{CustomConfigBuilder, RetryPolicy, RuleConfig, RuleOrigin, TechDetector, config::rule::RemoteOptions};
use std::{error::Error, path::PathBuf, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Build rule configuration
    // Use default configuration (recommended for most users)
    // Enable in Cargo.toml: rswappalyzer = { version = "0.3", features = ["embedded-rules"] }
    let config = RuleConfig::default();

    // 1.1 load raw rules from a local file
    // let mut config = RuleConfig::default();
    // config.origin = RuleOrigin::local_file("/path/to/rules.json".to_string());

    // 1.2 Local compiled Rule File
    // --------------------------
    // let config = RuleConfig {
    //     origin: RuleOrigin::local_compiled_file("/path/to/compiled_rules.bin"),
    //     ..RuleConfig::default()
    // };

    // 1.3 Remote Custom Rules (auto-cached)
    // --------------------------
    // const RULE_REMOTE_URL: &str =
    //     "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json";
    // let mut config = RuleConfig {
    //     origin: RuleOrigin::remote_custom(RULE_REMOTE_URL),
    //     ..RuleConfig::default()
    // };

    // 1.4 Custom Configuration Overrides (Optional)
    // ---------------------------------------------------------------------
    // Disable remote rule update checks
    // Useful for fully offline or deterministic environments
    // config.options.check_update = false;

    // HTTP timeout for remote rule downloads
    // config.options.remote_timeout = Duration::from_secs(15);

    // Retry policy for failed remote rule downloads
    // config.options.retry_policy = rswappalyzer::RetryPolicy::Times(3);

    // Specify a custom cache directory for downloaded rules
    // Defaults to the library-managed cache location
    // config.options.cache_dir = PathBuf::from("./custom_cache");

    // 1.5 Build a custom configuration example (chainable builder pattern)
    // let custom_config = CustomConfigBuilder::new()
    //     // Advanced option: remote rule download timeout (remote rules only)
    //     .remote_options(RemoteOptions {
    //         urls: vec!["https://your-rules-server.com/rules.json".to_string()],
    //         timeout: Duration::from_secs(15), // remote rule download timeout (remote rules only)
    //         retry: RetryPolicy::Times(3),     // number of retries for remote rule downloads
    //     })
    //     .cache_dir(PathBuf::from("./remote_cache"))
    //     .cache_file_name("my_fp_rules.json")
    //     // Advanced option: disable rule update checks
    //     .check_update(false)
    //     // Build the final configuration
    //     .build();

    // 1.6.1 Build a detector directly from cached compiled rule bytes
    // let compiled_bytes = fs::read("./compiled_rules.bin").unwrap();
    // 1.6.2 Create an empty rule configuration
    // (when using raw bytes, the config only keeps metadata)
    // let config = RuleConfig::empty();
    // 1.6.3 Construct the detector from compiled rule bytes
    // let detector = TechDetector::from_compiled_bytes(&compiled_bytes, config).unwrap();

    // 1.7.1 Read cached rule bytes from disk
    // let cached_rule_bytes = fs::read("./.cache/rswappalyzer/rswappalyzer_rules_cache.json").unwrap();
    // 1.7.2 Create an empty rule configuration
    // (no actual rule source is required when loading from bytes)
    // let config = RuleConfig::empty();
    // 1.7.3 Build the detector directly from cached rule bytes
    // let detector = TechDetector::from_cached_bytes(&cached_rule_bytes, config).unwrap();

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
