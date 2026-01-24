//! # 编码处理模块 (detection::encoding)
//! 封装HTML内容的编码检测与UTF-8转换逻辑，解决非UTF-8编码网页的识别准确性问题。
//! 核心特性：
//! 1. 多优先级编码检测：HTTP头 → HTML Meta → 自动检测 → 兜底替换
//! 2. 高性能转换：基于encoding_rs实现零拷贝/低拷贝转换
//! 3. 容错设计：转换失败时降级为from_utf8_lossy，保证程序稳定性

use http::HeaderMap;
use chardetng::EncodingDetector;
use encoding_rs::{Encoding, UTF_8, GBK, BIG5, EUC_JP, SHIFT_JIS, WINDOWS_1252};
use std::borrow::Cow;
use std::str;

/// 从Content-Type头提取编码（优先级最高）
fn extract_charset_from_content_type(ct: &str) -> Option<&'static Encoding> {
    let parts: Vec<&str> = ct.split(';').map(|s| s.trim()).collect();
    for part in parts {
        if part.starts_with("charset=") {
            let charset = part.split('=').nth(1)?.trim().to_lowercase();
            return match charset.as_str() {
                "utf-8" | "utf8" => Some(UTF_8),
                "gbk" | "gb2312" | "gb18030" => Some(GBK), // 增加GB18030兼容
                "big5" => Some(BIG5),
                "euc-jp" => Some(EUC_JP),
                "shift_jis" | "sjis" => Some(SHIFT_JIS),
                "iso-8859-1" | "latin1" | "windows-1252" => Some(WINDOWS_1252),
                _ => None,
            };
        }
    }
    None
}

/// 从HTML前1KB提取Meta Charset（优先级次之）
fn extract_meta_charset(html_head: &[u8]) -> Option<&'static Encoding> {
    // 优化：先尝试无损失转换，减少不必要的lossy转换
    let head_str = match str::from_utf8(html_head) {
        Ok(s) => s.to_ascii_lowercase(),
        Err(_) => String::from_utf8_lossy(html_head).to_ascii_lowercase(),
    };
    
    // 匹配 <meta charset="xxx"> 或 <meta http-equiv="Content-Type" content="text/html; charset=xxx">
    if let Some(charset_pos) = head_str.find("charset=") {
        let charset_part = &head_str[charset_pos + 8..];
        let end_pos = charset_part.find(&['"', '\'', ';', ' '][..]).unwrap_or(charset_part.len());
        let charset = charset_part[..end_pos].trim();
        return match charset {
            "utf-8" | "utf8" => Some(UTF_8),
            "gbk" | "gb2312" | "gb18030" => Some(GBK),
            "big5" => Some(BIG5),
            "euc-jp" => Some(EUC_JP),
            "shift_jis" | "sjis" => Some(SHIFT_JIS),
            "iso-8859-1" | "latin1" | "windows-1252" => Some(WINDOWS_1252),
            _ => None,
        };
    }
    None
}

/// 自动检测编码（兜底优先级）
fn auto_detect_encoding(body: &[u8]) -> &'static Encoding {
    let mut detector = EncodingDetector::new();
    // 仅读取前16KB用于检测（平衡准确率与性能）
    let detect_len = body.len().min(16 * 1024);
    detector.feed(&body[0..detect_len], true);
    // 优化：指定无语言提示，避免偏向性
    detector.guess(None, true)
}

/// 核心编码转换函数：将任意编码的HTML字节流转换为UTF-8字符串
/// 优先级：HTTP头 → HTML Meta → 自动检测 → from_utf8_lossy兜底
pub fn convert_to_utf8<'a>(body: &'a [u8], headers: &HeaderMap) -> Cow<'a, str> {
    // 快速路径：先尝试直接解析UTF-8，避免不必要的检测（提升已UTF-8内容的处理速度）
    if let Ok(s) = str::from_utf8(body) {
        return Cow::Borrowed(s);
    }

    // 步骤1：从HTTP头获取编码
    let mut target_encoding = headers
        .get("Content-Type")
        .and_then(|ct| ct.to_str().ok())
        .and_then(extract_charset_from_content_type);

    // 步骤2：从HTML Meta获取编码（头中无编码时）
    if target_encoding.is_none() && !body.is_empty() {
        let scan_len = body.len().min(1024);
        target_encoding = extract_meta_charset(&body[0..scan_len]);
    }

    // 步骤3：自动检测编码（仍无编码时）
    let encoding = target_encoding.unwrap_or_else(|| auto_detect_encoding(body));

    // 步骤4：精准转换为UTF-8
    let (converted, _, had_errors) = encoding.decode(body);
    if had_errors {
        // 转换出错，降级为兜底逻辑
        String::from_utf8_lossy(body)
    } else {
        converted
    }
}