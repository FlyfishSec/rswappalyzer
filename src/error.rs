//! 全局错误类型定义

use thiserror::Error;
use regex::Error as RegexError;
use serde_json::Error as SerdeJsonError;
use std::io::Error as IoError;
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum RswappalyzerError {
    // 规则相关错误
    #[error("规则加载失败：{0}")]
    RuleLoadError(String),
    #[error("规则缓存失败：{0}")]
    RuleCacheError(String),
    #[error("规则解析失败：{0}")]
    RuleParseError(String),

    // 编译相关错误
    #[error("正则编译失败：{0}")]
    RegexCompileError(#[from] RegexError),
    #[error("编译初始化失败：{0}")]
    CompilerInitError(String),

    // 检测相关错误
    #[error("检测器未初始化")]
    DetectorNotInitialized,
    #[error("检测失败：{0}")]
    DetectError(String),

    // 网络相关错误
    #[error("网络请求失败：{0}")]
    HttpError(#[from] reqwest::Error),

    // 序列化/反序列化错误
    #[error("JSON解析失败：{0}")]
    JsonError(#[from] SerdeJsonError),
    #[error("MessagePack序列化/反序列化失败：{0}")]
    MsgPackError(String),

    // 基础错误
    #[error("IO操作失败：{0}")]
    IoError(#[from] IoError),
    #[error("URL解析失败：{0}")]
    UrlError(#[from] UrlParseError),
    #[error("无效输入：{0}")]
    InvalidInput(String),
}

// 全局Result类型
pub type RswResult<T> = Result<T, RswappalyzerError>;