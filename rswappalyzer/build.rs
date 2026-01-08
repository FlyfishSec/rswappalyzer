// build.rs
// 1. 读取JSON格式构建配置
// 2. 读取原始Wappalyzer JSON规则文件并解析
// 3. 清洗规则并构建索引，编译为运行时高效格式
// 4. 序列化+可选压缩后写入二进制文件
// 5. 产物供主程序通过include_bytes!固化进最终二进制
use rswappalyzer_engine::source::WappalyzerParser;
use rswappalyzer_engine::{
    indexer::{RuleIndexer, RuleLibraryIndex},
    processor::RuleProcessor,
};
use serde::Deserialize;
use std::error::Error;
use std::{fs, path::Path};

/// 构建期配置结构体
#[derive(Debug, Deserialize)]
struct BuildConfig {
    /// 原始规则文件路径
    raw_rules_json_path: String,
    /// 编译后二进制产物文件名
    compiled_lib_output_name: String,
    /// 是否启用LZ4压缩
    enable_compress: bool,
    /// 分类映射JSON文件路径
    category_json_path: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    // 未开启嵌入式规则feature时不执行构建逻辑
    if std::env::var("CARGO_FEATURE_EMBEDDED_RULES").is_err() {
        return Ok(());
    }

    // 监听文件变更，触发自动重新构建
    println!("cargo:rerun-if-changed=build_config.json");
    println!("cargo:rerun-if-changed=data/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/");

    // 读取并解析构建配置文件
    let config_path = Path::new("build_config.json");
    let config_content = fs::read_to_string(config_path)
        .map_err(|e| format!("读取构建配置文件失败: {} - {}", config_path.display(), e))?;

    let cfg = serde_json::from_str::<BuildConfig>(&config_content)
        .map_err(|e| format!("解析build_config.json失败: {}", e))?;

    // 监听配置文件中配置的规则文件变更
    println!("cargo:rerun-if-changed={}", cfg.raw_rules_json_path);

    // 读取原始JSON规则文件
    let json_path = Path::new(&cfg.raw_rules_json_path);
    let json_content = fs::read_to_string(json_path)
        .map_err(|e| format!("读取规则文件失败: {} - {}", json_path.display(), e))?;

    // 解析原始规则并清洗为标准库格式
    let parser = WappalyzerParser::default();
    let raw_lib = parser
        .parse_to_rule_lib(&json_content)
        .map_err(|e| format!("解析JSON规则失败: {}", e))?;

    let rule_processor = RuleProcessor::default();
    let rule_library = rule_processor
        .clean_and_split_rules(&raw_lib)
        .map_err(|e| format!("规则清洗失败: {}", e))?;

    // 构建规则索引并编译为运行时库
    let rule_index = RuleLibraryIndex::from_rule_library(&rule_library)
        .map_err(|e| format!("构建规则索引失败: {}", e))?;

    let compiled_lib =
        RuleIndexer::build_compiled_library(&rule_index, Some(&cfg.category_json_path))
            .map_err(|e| format!("编译规则库失败: {}", e))?;

    // println!("cargo:warning=🔍 编译后库数据:");
    // println!(
    //     "cargo:warning=🔍 tech_patterns.len() = {}",
    //     compiled_lib.tech_patterns.len()
    // );
    // println!("cargo:warning=🔍 category_map.len() = {}", compiled_lib.category_map.len());
    // println!("cargo:warning=🔍 tech_meta.len() = {}", compiled_lib.tech_meta.len());
    // println!("cargo:warning=🔍 evidence_index.len() = {}", compiled_lib.evidence_index.len());
    // println!("cargo:warning=🔍 no_evidence_index.len() = {}", compiled_lib.no_evidence_index.len());

    // 序列化json
    let compiled_lib_bin = serde_json::to_vec(&compiled_lib)
        .map_err(|e| format!("JSON序列化编译规则库失败: {}", e))?;

    // 调试代码
    // let debug_json_path = Path::new("compiled_rules_debug.json");
    // fs::write(&debug_json_path, &compiled_lib_bin)
    //     .map_err(|e| format!("写入调试 JSON 失败: {} - {}", debug_json_path.display(), e))?;
    // println!("✅ 调试 JSON 已写入当前目录: {}", debug_json_path.display());

    // 根据配置选择是否进行LZ4压缩
    let compressed_lib = if cfg.enable_compress {
        use lz4_flex::compress_prepend_size;
        compress_prepend_size(&compiled_lib_bin)
    } else {
        compiled_lib_bin
    };

    // 将处理后的二进制产物写入构建输出目录
    let out_dir = std::env::var("OUT_DIR")?;
    let out_path_lib = Path::new(&out_dir).join(&cfg.compiled_lib_output_name);
    fs::write(&out_path_lib, &compressed_lib)
        .map_err(|e| format!("写入编译库二进制失败: {} - {}", out_path_lib.display(), e))?;

    println!(
        "编译库写入完成: {:?} → {}",
        out_dir, cfg.compiled_lib_output_name
    );

    // 向编译环境注入构建配置常量，供lib.rs读取
    println!(
        "cargo:rustc-env=COMPILED_LIB_FILENAME={}",
        cfg.compiled_lib_output_name
    );

    Ok(())
}
