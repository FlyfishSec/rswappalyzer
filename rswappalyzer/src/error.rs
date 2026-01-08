//! 全局错误类型定义
//! 统一封装所有业务错误，基于thiserror实现类型安全的错误处理
use thiserror::Error;

use http::header::ToStrError;
use rswappalyzer_engine::CoreError;
use serde_json::Error as SerdeJsonError;
use std::{
    io::Error as IoError,
    time::SystemTimeError,
};
use url::ParseError as UrlParseError;

/// 全局错误枚举
/// 封装所有业务场景的错误类型，支持From转换和结构化错误信息
#[derive(Error, Debug)]
pub enum RswappalyzerError {
    /// 内核核心错误（透传）
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    // ===================== 基础IO/解析错误 =====================
    /// IO操作失败（文件读写/网络IO等）
    #[error("IO operation failed: {0}")]
    IoError(#[from] IoError),

    /// URL解析失败（格式错误/非法字符等）
    #[error("URL parse failed: {0}")]
    UrlError(#[from] UrlParseError),

    /// 无效输入参数（参数格式/范围错误）
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// HTTP Header字段转字符串失败
    #[error("Header field to string conversion failed: {0}")]
    HeaderToStrError(#[from] ToStrError),

    /// 系统时间计算失败（时间戳转换/比较等）
    #[error("System time calculation failed: {0}")]
    SystemTimeError(#[from] SystemTimeError),

    // ===================== 规则相关错误 =====================
    /// 规则加载失败（本地/远程加载/缓存读取等）
    #[error("Rule load failed: {0}")]
    RuleLoadError(String),

    /// 规则格式转换失败（数据结构映射/字段匹配等）
    #[error("Rule conversion failed: {0}")]
    RuleConvertError(String),

    /// 规则缓存操作失败（缓存写入/读取/删除等）
    #[error("Rule cache operation failed: {0}")]
    RuleCacheError(String),

    /// 规则解析失败（JSON/YAML解析/语法错误等）
    #[error("Rule parse failed: {0}")]
    RuleParseError(String),

    // ===================== 检测相关错误 =====================
    /// 检测器未初始化（调用检测前未完成初始化）
    #[error("Detector not initialized: {0}")]
    DetectorNotInitialized(String),

    /// 检测器初始化失败（配置错误/资源不足等）
    #[error("Detector initialization failed: {0}")]
    DetectorInitError(String),

    /// 技术检测失败（规则匹配/数据提取等）
    #[error("Detection failed: {0}")]
    DetectError(String),

    // ===================== 网络相关错误 =====================
    /// 网络操作失败（请求发送/响应解析/连接超时等）
    #[error("Network operation failed: {0}")]
    NetworkError(String),

    // ===================== 序列化/反序列化错误 =====================
    /// JSON序列化/反序列化失败
    #[error("JSON parse/serialize failed: {0}")]
    JsonError(#[from] SerdeJsonError),

    // #[error("MessagePack decode failed: {0}")]
    // MsgPackDecode(#[from] decode::Error),
    // 
    // #[error("MessagePack encode failed: {0}")]
    // MsgPackEncode(#[from] encode::Error),

    // ===================== 异步/特性相关错误 =====================
    /// 异步任务执行失败（任务panic/取消/超时等）
    #[error("Async task execution failed: {0}")]
    AsyncTaskError(String),

    /// 功能特性未开启（如remote-loader未启用）
    #[error("Feature disabled: {0}")]
    FeatureDisabled(String)
}

/// 全局Result类型别名
/// 统一使用RswappalyzerError作为错误类型
pub type RswResult<T> = Result<T, RswappalyzerError>;