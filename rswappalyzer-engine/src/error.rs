//! rswappalyzer-core 内核错误定义
//! 封装内核层所有核心错误，与业务层错误解耦，基于thiserror实现类型安全处理
use thiserror::Error;

use regex::Error as RegexError;

/// 内核核心错误枚举
/// 封装rswappalyzer-core层所有错误类型，专注内核级逻辑错误
#[derive(Error, Debug)]
pub enum CoreError {
    // ===================== 规则相关错误 =====================
    /// 规则加载失败（内核层规则读取/加载逻辑错误）
    #[error("Rule load failed: {0}")]
    RuleLoadError(String),

    /// 规则格式转换失败（内核层数据结构映射错误）
    #[error("Rule conversion failed: {0}")]
    RuleConvertError(String),

    /// 规则缓存操作失败（内核层缓存逻辑错误）
    #[error("Rule cache operation failed: {0}")]
    RuleCacheError(String),

    /// 规则解析失败（内核层规则语法/格式解析错误）
    #[error("Rule parse failed: {0}")]
    RuleParseError(String),

    // ===================== 编译相关错误 =====================
    /// 正则表达式编译失败（正则语法错误/不支持的特性）
    #[error("Regex compilation failed: {0}")]
    RegexCompileError(#[from] RegexError),

    /// 编译器初始化失败（编译环境/配置错误）
    #[error("Compiler initialization failed: {0}")]
    CompilerInitError(String),

    // ===================== 检测相关错误 =====================
    /// 检测器未初始化（内核层检测器调用前未完成初始化）
    #[error("Detector not initialized: {0}")]
    DetectorNotInitialized(String),

    /// 检测器初始化失败（内核层检测器配置/资源错误）
    #[error("Detector initialization failed: {0}")]
    DetectorInitError(String),

    /// 技术检测失败（内核层规则匹配/特征提取错误）
    #[error("Detection failed: {0}")]
    DetectError(String),

    // ===================== 内核基础错误 =====================
    /// 无效输入参数（内核层输入校验失败）
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// 内核内部错误（非业务逻辑的底层错误）
    #[error("Core internal error: {0}")]
    InternalError(String),

    /// 不支持的匹配范围（传入的MatchScope不在内核支持列表）
    #[error("Unsupported match scope: {0:?}")]
    UnsupportedMatchScope(crate::core::MatchScope),

    /// 内核逻辑不变量被破坏（核心算法约束违反，属于严重错误）
    #[error("Core invariant violation: {0}")]
    InvariantViolation(&'static str),

    /// 非法的规则状态转换（规则生命周期状态非法变更）
    #[error("Invalid rule state transition: {0}")]
    InvalidStateTransition(String),
}

/// 内核层全局Result类型别名
/// 统一使用CoreError作为内核层错误类型
pub type CoreResult<T> = Result<T, CoreError>;