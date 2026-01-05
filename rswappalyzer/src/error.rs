//! 全局错误类型定义
use thiserror::Error;
use regex::Error as RegexError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, time::SystemTimeError};
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum RswappalyzerError {
    // 规则相关错误
    #[error("规则加载失败：{0}")]
    RuleLoadError(String),
    #[error("规则转换失败：{0}")]
    RuleConvertError(String),
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
    #[error("检测器未初始化: {0}")]
    DetectorNotInitialized(String),
    #[error("检测器初始化失败: {0}")]
    DetectorInitError(String),
    #[error("检测失败：{0}")]
    DetectError(String),

    // 网络相关错误
    #[error("网络相关错误：{0}")]
    NetworkError(String),
    #[error("Header 字段转字符串失败：{0}")]
    HeaderToStrError(#[from] http::header::ToStrError),
    
    // 序列化/反序列化错误
    #[error("JSON解析失败：{0}")]
    JsonError(#[from] SerdeJsonError),
    // #[error("MessagePack反序列化失败：{0}")]
    // MsgPackDecode(#[from] decode::Error),
    // #[error("MessagePack序列化失败：{0}")]
    // MsgPackEncode(#[from] encode::Error),

    // 基础错误
    #[error("IO操作失败：{0}")]
    IoError(#[from] IoError),
    #[error("URL解析失败：{0}")]
    UrlError(#[from] UrlParseError),
    #[error("无效输入：{0}")]
    InvalidInput(String),

    #[error("系统时间计算失败：{0}")]
    SystemTimeError(#[from] SystemTimeError),

    #[error("异步任务执行失败：{0}")]
    AsyncTaskError(String),
}

// 全局Result类型
pub type RswResult<T> = Result<T, RswappalyzerError>;