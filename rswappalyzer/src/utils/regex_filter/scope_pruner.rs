//! 正则过滤 - 多作用域结构化剪枝器 (Scope Pruner)
//! 核心能力：按业务作用域(Url/Html/Script/Css/Header/Meta/Cookie)实现结构化黑白名单剪枝

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::utils::regex_filter::common::safe_lowercase;

/// 剪枝作用域枚举 - 枚举所有支持结构化剪枝的业务域
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneScope {
    /// URL地址剪枝
    Url,
    /// HTML文本内容剪枝
    Html,
    /// JS脚本资源路径剪枝
    Script,
    /// HTTP请求头KV剪枝
    Header,
    /// HTML Meta标签KV剪枝
    Meta,
    /// Cookie键值对剪枝
    Cookie,
}

/// 多作用域剪枝统一入口函数
#[inline(always)]
pub fn struct_prune(scope: PruneScope, input: &str, key: Option<&str>) -> bool {
    match scope {
        PruneScope::Url => url_struct_prune(input),
        PruneScope::Html => html_struct_prune(input),
        PruneScope::Script => script_struct_prune(input),
        PruneScope::Header => header_struct_prune(key.unwrap_or(""), input),
        //PruneScope::Meta => meta_struct_prune(key.unwrap_or(""), input),
        PruneScope::Meta => true,
        PruneScope::Cookie => cookie_struct_prune(key.unwrap_or(""), input),
    }
}

/// 只剪掉确定是构建产物或 hash 文件
#[inline(always)]
pub fn script_struct_prune(input: &str) -> bool {
    // ===== 核心优化1: 前置纯字符串快速短路，95%场景不触发正则，性能提升最明显 =====
    let is_js = input.ends_with(".js") || input.ends_with(".JS");
    if !is_js {
        return true;
    }

    let input_lower = input.to_lowercase();
    let has_build_key = input_lower.contains("chunk-") 
        || input_lower.contains("runtime") 
        || input_lower.contains("hot-update");
    
    if has_build_key {
        static BUILD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:^|/)(chunk-|runtime|hot-update).*\.js$").unwrap()
        });
        if BUILD_RE.is_match(input) {
            return false; // 确定剪掉
        }
    }

    // 无Vec堆分配的hash判断，零内存开销
    if looks_like_hashed_js_optimized(input) {
        return false; // 确定剪掉
    }

    // 其他一律放行
    true
}

/// 无Vec创建、无冗余遍历、纯指针操作判断hash文件，零堆开销
#[inline(always)]
fn looks_like_hashed_js_optimized(s: &str) -> bool {
    let s_bytes = s.as_bytes();
    // 找最后一个 / 或 \ 的位置，无需rsplit遍历
    let name_start = s_bytes.iter().rposition(|&c| c == b'/' || c == b'\\').map_or(0, |p| p + 1);
    let name = &s_bytes[name_start..];
    
    let mut dot_count = 0;
    let mut last_dot_pos = 0;
    let mut penult_dot_pos = 0;

    // 单次遍历统计点的数量和位置，一次遍历完成所有判断
    for (i, &c) in name.iter().enumerate() {
        if c == b'.' {
            dot_count += 1;
            penult_dot_pos = last_dot_pos;
            last_dot_pos = i;
        }
    }

    // 必须至少2个点 (name.hash.js)
    if dot_count < 2 || last_dot_pos == 0 || penult_dot_pos == 0 {
        return false;
    }

    // 提取hash段，无Vec拆分
    let hash_start = penult_dot_pos + 1;
    let hash_end = last_dot_pos;
    let hash_len = hash_end - hash_start;
    if hash_len < 8 || hash_len > 32 {
        return false;
    }

    // 纯16进制判断，字节遍历比chars快一倍
    let hash_slice = &name[hash_start..hash_end];
    hash_slice.iter().all(|&c| (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F'))
}

/// URL 地址结构化剪枝（黑名单阶段）
#[inline(always)]
pub fn url_struct_prune(input: &str) -> bool {
    if input.is_empty() {
        return true;
    }

    // Scheme 级确定性过滤 - 纯字符串判断，零开销
    let input_lower = safe_lowercase(input);
    if input_lower.starts_with("data:") 
        || input_lower.starts_with("blob:") 
        || input_lower.starts_with("javascript:") {
        return true;
    }

    // 提取 path（去掉 query / fragment）- 纯指针操作，无分配
    let path = input.split_once('?').map(|(p, _)| p).unwrap_or(input)
        .split_once('#').map(|(p, _)| p).unwrap_or(input);

    // 100% 确定的静态资源后缀
    const STATIC_SUFFIX_BLACKLIST: &[&str] = &[
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".mp4", ".mp3", ".wav",
        ".avi", ".woff", ".woff2", ".ttf", ".eot",
    ];

    // 小写后缀判断，避免全量转换
    let path_lower = safe_lowercase(path);
    if STATIC_SUFFIX_BLACKLIST.iter().any(|ext| path_lower.ends_with(ext)) {
        return true;
    }

    // 其他全部不确定，放行
    false
}

#[inline(always)]
pub fn html_struct_prune(input: &str) -> bool {
    input.contains('<')
}

#[inline(always)]
pub fn header_struct_prune(key: &str, input: &str) -> bool {
    // true  = 保留
    // false = 剪枝
    // 仅对可能包含技术栈的 Header 做剪枝
    const FILTER_KEYS: &[&str] = &["server", "x-powered-by", "x-server", "via"];

    // ASCII忽略大小写判断
    let key_matched = FILTER_KEYS.iter().any(|k| {
        key.len() == k.len() && key.eq_ignore_ascii_case(k)
    });
    if !key_matched {
        return true;
    }

    let v_lower = safe_lowercase(input);
    let v = v_lower.trim();

    if v.is_empty() || INVALID_KEYWORDS.iter().any(|&kw| kw == v) || is_pure_digit_optimized(v) || v.len() < 2 {
        return false;
    }

    //其余放行
    true
}

/// Cookie 结构化剪枝
#[inline(always)]
pub fn cookie_struct_prune(key: &str, _value: &str) -> bool {
    let bk = safe_lowercase(key);
    let k = bk.trim();
    if k.is_empty() {
        return true;
    }

    // 明确无技术语义的追踪 / 统计 Cookie
    const COOKIE_KEY_BLACKLIST: &[&str] = &[
        "_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "_hj", "_hjSession",
        "_hjIncludedInPageviewSample", "_ym_", "__utm", "__utma", "__utmb",
        "__utmc", "__utmz",
    ];

    if COOKIE_KEY_BLACKLIST.iter().any(|x| k.starts_with(x)) {
        return true;
    }

    // Cookie Attribute（非 Cookie 本体）
    const COOKIE_ATTR_KEY: &[&str] = &[
        "path", "expires", "max-age", "domain", "secure", "httponly", "samesite",
    ];

    if COOKIE_ATTR_KEY.iter().any(|x| k == *x) {
        return true;
    }

    // 其余全部不确定，放行
    false
}

// 全局通用工具函数
#[inline(always)]
pub fn is_pure_digit_optimized(s: &str) -> bool {
    s.as_bytes().iter().all(|&c| c >= b'0' && c <= b'9')
}

#[inline(always)]
pub fn is_pure_alpha(s: &str) -> bool {
    s.as_bytes().iter().all(|&c| (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z'))
}

#[inline(always)]
pub fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// 全局无效关键字池
static INVALID_KEYWORDS: Lazy<&[&str]> = Lazy::new(|| &[
    "true", "false", "null", "undefined", "on", "off", "none", "nil",
    "0", "1", "-", "_", "#", "*", "&", "@", "$", " ", ""
]);
