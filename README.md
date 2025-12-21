# rswappalyzer

A high-performance Rust implementation of **Wappalyzer**, designed for fast and accurate website technology stack detection.  
It leverages streaming HTML parsing and optimized pattern matching to deliver reliable detection capabilities for Rust-based web crawlers, security scanners, and monitoring systems.

高性能 **Wappalyzer** Rust 实现，用于快速、精准地检测网站技术栈。  
基于流式 HTML 解析和优化的模式匹配技术，为 Rust 生态的爬虫、安全扫描器和监控系统提供可靠的技术栈识别能力。

---

## Features | 功能

| Feature | Description | 核心功能 | 描述 |
| --------- | ------------ | ------ | ------ |
| Streaming HTML Parsing with html5ever | Replaces regex-based tag extraction with the industry-standard html5ever HTML parser. Directly extracts script/meta tags from the streaming response body without loading the entire HTML into memory, making it ideal for large web pages and memory-constrained environments. | 基于 html5ever 的流式 HTML 解析 | 摒弃传统正则提取标签的方案，采用工业级 html5ever 解析器，无需加载完整 HTML 内容，即可从流式响应中精准提取 script/meta 标签，适配大网页解析与内存敏感场景。 |
| Concurrent-Safe Detection | The core detector is designed to be thread-safe (Send + Sync) and can be shared across multiple async tasks/threads. Enables efficient batch detection in distributed crawler clusters or multi-threaded scanning tools. | 并发安全的检测能力 | 核心检测器采用线程安全（Send + Sync）设计，可在多个异步任务 / 线程间共享，适配分布式爬虫集群、多线程扫描工具的批量检测需求。 |
| Comprehensive Detection | Identifies technologies from HTTP headers, HTML meta tags, script sources, and response bodies. | 全面检测能力 | 从 HTTP 响应头、HTML Meta 标签、Script 资源地址、响应正文等多维度识别技术栈。 |
| Seamless Integration for Rust Projects | Designed as a pure Rust library with no hidden external dependencies or system requirements. Exposes a clear, idiomatic API that fits naturally into asynchronous Rust workflows (e.g., tokio-based crawlers). Supports custom rule paths and proxy configurations for enterprise-level deployments. | Rust 项目无缝集成 | 纯 Rust 库设计，无隐藏外部依赖与系统级依赖，提供符合 Rust 习惯的简洁 API，可无缝融入异步 Rust 工作流（如 tokio 爬虫）；支持自定义规则路径与代理配置，满足企业级部署需求。 |

---

## Installation | 安装

Add this to your `Cargo.toml`:

```cmd
cargo add rswappalyzer
```

Or manually:

```toml
[dependencies]
rswappalyzer = "0.1.0"
```

## Quick Start | 快速开始

<!-- ### Basic Usage | 基础用法 -->

```rust
use rswappalyzer::{
    init_wappalyzer,
    detect_technologies_wappalyzer,
    detect_technologies_wappalyzer_lite,
    rule::{Technology, TechnologyLite},
    RswResult,
};
use reqwest::header::HeaderMap;

#[tokio::main]
async fn main() -> RswResult<()> {
    // 1. Initialize detector (load rules from cache or GitHub)
    init_wappalyzer().await?;
    println!("✅ Wappalyzer initialized successfully");

    // 2. Prepare detection data (HTTP headers + target URLs + HTML body)
    let mut headers = HeaderMap::new();
    headers.insert("Server", "Apache/2.4.41".parse()?);
    headers.insert("X-Powered-By", "PHP/7.4.0".parse()?);

    let urls = &["https://example.com"];
    let body = r#"
        <html>
            <head>
                <meta name="generator" content="WordPress 6.4">
            </head>
            <body>
                <script src="/static/js/jquery-3.7.1.min.js"></script>
            </body>
        </html>
    "#.as_bytes();

    // 3a. Run full detection (returns Technology with detailed info)
    let full_techs: Vec<Technology> = detect_technologies_wappalyzer(&headers, urls, body)?;
    println!("\nFull Detection Results | 完整检测结果:");
    for (idx, tech) in full_techs.iter().enumerate() {
        println!(
            "{}. {} (Confidence | 置信度: {}%){}",
            idx + 1,
            tech.name,
            tech.confidence,
            tech.version.as_ref().map_or("", |v| &format!(" (Version | 版本: {})", v))
        );
    }

    // 3b. Run lite detection (returns TechnologyLite for faster, lightweight detection)
    let lite_techs: Vec<TechnologyLite> = detect_technologies_wappalyzer_lite(&headers, urls, body)?;
    println!("\nLite Detection Results | 精简检测结果:");
    for (idx, tech) in lite_techs.iter().enumerate() {
        println!(
            "{}. {} (Confidence | 置信度: {}%)",
            idx + 1,
            tech.name,
            tech.confidence
        );
    }

    Ok(())
}
```

### API Overview | API 说明

| Function | Returns | Description | 返回值 | 描述 |
| ---------- | -------- | ------------- | -------- | ------ |
| `detect_technologies_wappalyzer` | `Vec<Technology>` | Full detection with detailed version info, confidence, categories. | `Vec<Technology>` | 返回完整检测结果 |
| `detect_technologies_wappalyzer_lite` | `Vec<TechnologyLite>` | Lightweight/faster detection, only name and confidence. | `Vec<TechnologyLite>` | 返回精简检测结果 |

---
<!-- 
## Core Modules | 核心模块

| Module | Responsibility | 模块 | 职责 |
| -------- | --------------- | ------ | ------ |
| config | Global configuration management (proxy, cache path, timeout) | 全局配置管理 | 代理、缓存路径、超时时间 |
| error | Unified error type (`RswappalyzerError`) and result type (`RswResult`) | 统一错误类型 | 错误类型和结果类型封装 |
| extractor | HTML streaming parser (`html5ever`) for script/meta tags | HTML 流式解析 | 流式解析器，提取 script 和 meta 标签 |
| rule | Rule models (`TechRule`, `CategoryRule`, `RuleLibrary`) and loading logic | 规则模型与加载 | 定义规则模型并提供加载逻辑 |
| compiler | Regex compilation optimization & Aho-Corasick pattern matching | 正则编译优化 | 正则按需编译，多模式匹配优化 |
| cache | MessagePack binary cache for rule libraries | 规则库缓存 | 提供二进制缓存，减少启动耗时 |
| detector | Core detection logic combining multi-source data | 核心检测逻辑 | 整合 HTTP/HTML/脚本资源检测技术栈 |

--- -->

## Data Sources | 规则源

The following projects are used as rule sources:

- **WebAppAnalyzer**  
  <https://github.com/enthec/webappanalyzer>

- **Wappalyzer (HTTPArchive)**  
  <https://github.com/HTTPArchive/wappalyzer>

## References | 参考项目

- **RustedWappalyzer**  
  <https://github.com/shart123456/RustedWappalyzer>

- **wappalyzergo**  
  <https://github.com/projectdiscovery/wappalyzergo>

## Author | 作者

FlyfishSec

---

## License | 许可证

This project is licensed under the MIT License.  
本项目基于 **MIT 许可证** 开源。
