use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// 匹配作用域枚举，定义所有支持的检测维度
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum MatchScope {
    Url,
    Html,
    Js,
    Script,
    ScriptSrc,
    Header,
    Cookie,
    Meta,
}

impl Display for MatchScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchScope::Url => write!(f, "url"),
            MatchScope::Html => write!(f, "html"),
            MatchScope::Js => write!(f, "html"),
            MatchScope::Script => write!(f, "script"),
            MatchScope::ScriptSrc => write!(f, "script"),
            MatchScope::Meta => write!(f, "meta"),
            MatchScope::Header => write!(f, "header"),
            MatchScope::Cookie => write!(f, "cookie"),
        }
    }
}

/// 匹配类型枚举，标记每条模式的匹配方式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchType {
    Contains,
    Regex,
    Exists, // 存在性检测（仅用于 headers/meta 的空值场景）
}

impl Default for MatchType {
    fn default() -> Self {
        MatchType::Regex
    }
}

/// 匹配条件枚举
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    #[default]
    Or,
}

/// 规则证据类型枚举
/// 用于区分不同类型的匹配规则，适配不同的执行逻辑
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    // /// 基于Token/Literal/Any/Contains的规则（需要证据匹配）
    // TokenBased,
    /// 仅检查存在性的规则（Header/Cookie键存在即可，无必现Token）
    /// 基于Literal/Any/Contains的规则（需要证据匹配）
    LiteralBased,
    /// 仅检查存在性的规则（Header/Cookie键存在即可，无必现Token）
    ExistsOnly,
    /// 纯正则规则（无必现字面量，仅靠正则匹配）
    NoLiteral,
}
