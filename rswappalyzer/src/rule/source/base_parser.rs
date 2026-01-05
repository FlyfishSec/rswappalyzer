//! 通用规则源解析器 Trait + 类型擦除封装

use std::sync::Arc;
use std::any::Any;

//use reqwest::Response;
use serde::de::DeserializeOwned;
use crate::{
    FingerprintHubParser, WappalyzerGoParser, 
    error::{RswResult, RswappalyzerError},
};
use async_trait::async_trait;

// 规则文件类型枚举
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleFileType {
    WappalyzerGoJson,
    FingerprintHubJson,
    //RswappalyzerMsgpack,
}

impl RuleFileType {
    pub fn file_suffix(&self) -> &str {
        match self {
            RuleFileType::WappalyzerGoJson => "json",
            RuleFileType::FingerprintHubJson => "json",
            //RuleFileType::RswappalyzerMsgpack => "mp",
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            RuleFileType::WappalyzerGoJson => "wappalyzer_go",
            RuleFileType::FingerprintHubJson => "fingerprinthub",
            //RuleFileType::RswappalyzerMsgpack => "rswappalyzer",
        }
    }
}

// 泛型解析器特质
#[async_trait]
pub trait RuleSourceParser<O>: std::fmt::Debug + Send + Sync + Any + 'static
where
    O: DeserializeOwned + Send + Sync + 'static,
{
    fn rule_file_type(&self) -> RuleFileType;

    fn parse_original_from_str(&self, _content: &str) -> RswResult<O> {
        Err(RswappalyzerError::RuleParseError(
            "当前解析器不支持从字符串解析原始规则".to_string(),
        ))
    }

    fn parse_original_from_bytes(&self, _bytes: &[u8]) -> RswResult<O> {
        Err(RswappalyzerError::RuleParseError(
            "当前解析器不支持从字节流解析原始规则".to_string(),
        ))
    }

    #[cfg(feature = "remote-loader")]
    async fn parse_original_from_response(&self, _response: reqwest::Response) -> RswResult<O> {
        Err(RswappalyzerError::RuleParseError(
            "当前解析器不支持从 HTTP 响应解析原始规则".to_string(),
        ))
    }
}

// 类型擦除核心：统一封装解析接口
#[derive(Debug, Clone)]
pub struct ErasedRuleSourceParser {
    rule_file_type: RuleFileType,
    parser: Arc<dyn Any + Send + Sync + 'static>,
}

impl ErasedRuleSourceParser {
    /// 创建封装对象（类型擦除）
    pub fn new<O, P>(parser: P) -> Self
    where
        O: DeserializeOwned + Send + Sync + 'static,
        P: RuleSourceParser<O> + Any + Send + Sync + 'static,
    {
        Self {
            rule_file_type: parser.rule_file_type(),
            parser: Arc::new(parser),
        }
    }

    /// 获取规则文件类型
    pub fn rule_file_type(&self) -> RuleFileType {
        self.rule_file_type.clone()
    }

    /// 向下转型引用
    pub fn downcast_ref<O, P>(&self) -> Option<&P>
    where
        O: DeserializeOwned + Send + Sync + 'static,
        P: RuleSourceParser<O> + Any + 'static,
    {
        self.parser.downcast_ref::<P>()
    }

    /// 向下转型 Arc
    pub fn downcast_arc<O, P>(self) -> Option<Arc<P>>
    where
        O: DeserializeOwned + Send + Sync + 'static,
        P: RuleSourceParser<O> + Any + 'static,
    {
        Arc::downcast(self.parser).ok()
    }

    /// 从字节解析规则库（上层统一调用）
    pub fn parse_from_bytes(&self, bytes: &[u8]) -> RswResult<Box<dyn Any + Send + Sync>> {
        match self.rule_file_type {
            RuleFileType::WappalyzerGoJson => {
                let parser = self.downcast_ref::<_, WappalyzerGoParser>()
                    .ok_or_else(|| RswappalyzerError::RuleLoadError("类型转换失败".to_string()))?;
                // 返回原始类型 WappalyzerOriginalRuleLibrary
                parser.parse_original_from_bytes(bytes)
                    .map(|lib| Box::new(lib) as Box<dyn Any + Send + Sync>)
            }
            RuleFileType::FingerprintHubJson => {
                let parser = self.downcast_ref::<_, FingerprintHubParser>()
                    .ok_or_else(|| RswappalyzerError::RuleLoadError("类型转换失败".to_string()))?;
                // 返回原始类型 FingerprintHubOriginalRuleLibrary
                parser.parse_original_from_bytes(bytes)
                    .map(|lib| Box::new(lib) as Box<dyn Any + Send + Sync>)
            }
            // RuleFileType::RswappalyzerMsgpack => {
            //     // 反序列化为 CachedTechRule（缓存结构），而非 RuleLibrary
            //     let cached_rules: Vec<CachedTechRule> = from_slice(bytes).map_err(|e| {
            //         RswappalyzerError::RuleLoadError(format!("反序列化 msgpack 失败：{}", e))
            //     })?;
                
            //     // CachedTechRule → RuleLibrary
            //     let rule_lib = self.cached_to_rule_library(cached_rules)?;
                
            //     Ok(Box::new(rule_lib) as Box<dyn Any + Send + Sync>)
            // }
        }
    }

    /// 异步从 HTTP Response 解析规则库
    #[cfg(feature = "remote-loader")]
    pub async fn parse_from_response(&self, response: reqwest::Response) -> RswResult<Box<dyn Any + Send + Sync>> {
        match self.rule_file_type {
            RuleFileType::WappalyzerGoJson => {
                let parser = self.downcast_ref::<_, WappalyzerGoParser>()
                    .ok_or_else(|| RswappalyzerError::RuleLoadError("类型转换失败".to_string()))?;
                // 返回原始类型
                parser.parse_original_from_response(response)
                    .await
                    .map(|lib| Box::new(lib) as Box<dyn Any + Send + Sync>)
            }
            RuleFileType::FingerprintHubJson => {
                let parser = self.downcast_ref::<_, FingerprintHubParser>()
                    .ok_or_else(|| RswappalyzerError::RuleLoadError("类型转换失败".to_string()))?;
                // 返回原始类型
                parser.parse_original_from_response(response)
                    .await
                    .map(|lib| Box::new(lib) as Box<dyn Any + Send + Sync>)
            }
            // RuleFileType::RswappalyzerMsgpack => {
            //     let bytes = response.bytes().await.map_err(|e| {
            //         RswappalyzerError::RuleLoadError(format!("读取 msgpack 响应体失败：{}", e))
            //     })?;
                
            //     // 反序列化为缓存结构
            //     let cached_rules: Vec<CachedTechRule> = from_slice(&bytes).map_err(|e| {
            //         RswappalyzerError::RuleLoadError(format!("反序列化 msgpack 失败：{}", e))
            //     })?;
                
            //     // 转换为运行时结构
            //     let rule_lib = self.cached_to_rule_library(cached_rules)?;
                
            //     Ok(Box::new(rule_lib) as Box<dyn Any + Send + Sync>)
            // }
        }
    }

    // CachedTechRule → RuleLibrary 转换逻辑
    // fn cached_to_rule_library(&self, cached_rules: Vec<CachedTechRule>) -> RswResult<RuleLibrary> {
    //     use std::collections::HashMap;
    //     use crate::rule::core::ParsedTechRule;
    //     use crate::rule::indexer::scope::MatchRuleSet;

    //     let mut core_tech_map = HashMap::new();
    //     let mut category_rules = HashMap::new();

    //     for cached in cached_rules {
    //         let tech_name = cached.basic.tech_name.clone()
    //             .ok_or_else(|| RswappalyzerError::RuleLoadError("CachedTechRule 缺少 tech_name".to_string()))?;

    //         // 转换 CachedScopeRule → MatchRuleSet（复用你原有逻辑）
    //         let mut match_rules = HashMap::new();
    //         for (scope, cached_scope_rule) in cached.rules {
    //             let rule_set = MatchRuleSet::from_cached(&scope, cached_scope_rule);
    //             match_rules.insert(scope, rule_set);
    //         }

    //         // 构建 ParsedTechRule（运行时结构）
    //         let parsed = ParsedTechRule {
    //             basic: cached.basic,
    //             match_rules,
    //         };

    //         core_tech_map.insert(tech_name, parsed);
    //     }

    //     if core_tech_map.is_empty() {
    //         return Err(RswappalyzerError::RuleLoadError(
    //             "CachedTechRule 转换后无有效规则".to_string()
    //         ));
    //     }

    //     // 补充默认分类规则
    //     category_rules = crate::rule::core::category_rule::get_default_categories();

    //     Ok(RuleLibrary {
    //         core_tech_map,
    //         category_rules,
    //     })
    // }

}