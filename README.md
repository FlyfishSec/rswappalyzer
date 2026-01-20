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
use rswappalyzer::detector;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Send HTTP request
    let client = Client::new();
    let url = "https://example.com";
    let resp = client.get(url).send().await?;

    // 2. Extract headers and body
    let headers: HeaderMap = resp.headers().clone();
    let body = resp.bytes().await?;

    // 3. Run technology detection
    let result = detector::detect(&headers, &[url], body.as_ref()).await?;

    // 4. Get detected technology list
    println!("Technologies: {:?}", result.tech_list());

    // 5. Get full structured result as JSON
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
