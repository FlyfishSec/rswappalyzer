//! 模式列表与键值对映射

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::pattern::Pattern;

/// 列表型模式（针对 url/html/script/script_src 等连续匹配维度）
/// 扫描时按技术名称批量匹配
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternList(pub Vec<Pattern>);

/// 键值对型模式（针对 meta/header 等 KV 类型匹配）
/// Key = 元信息名 / Header 名, Value = 技术规则列表
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMap(pub HashMap<String, Vec<Pattern>>);
