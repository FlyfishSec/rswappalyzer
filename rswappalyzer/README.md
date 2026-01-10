# rswappalyzer 🚀

A high-performance Wappalyzer rule detection engine.

极速 ***wappalyzer*** 规则检测引擎

---

## Installation 📦 | 安装

Add this to your `Cargo.toml`:

```cmd
cargo add rswappalyzer
```

## Quick Start ⚡ | 快速开始

```rust
use reqwest::Client;
use reqwest::header::HeaderMap;
use rswappalyzer::detector::detect;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = "https://example.com";
    let resp = client.get(url).send().await?;
    let headers: HeaderMap = resp.headers().clone();
    let body = resp.bytes().await?;

    let detect_result = detect(&headers, &[url], body.as_ref()).await?;

    println!("{}", detect_result.to_json_pretty()?);

    Ok(())
}
```

Output:

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
