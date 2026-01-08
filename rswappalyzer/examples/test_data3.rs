//! 测试数据模块 - 修复原始字符串中#!符号的语法冲突
use http::header::{HeaderMap, HeaderName, HeaderValue};

/// 获取 IIS 服务器的测试响应头
#[allow(dead_code)]
pub fn get_test_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    
    // Content-Type: text/html
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html"),
    );
    
    // Last-Modified: Sat, 06 Sep 2025 07:34:01 GMT
    headers.insert(
        HeaderName::from_static("last-modified"),
        HeaderValue::from_static("Sat, 06 Sep 2025 07:34:01 GMT"),
    );
    
    // Accept-Ranges: bytes
    headers.insert(
        HeaderName::from_static("accept-ranges"),
        HeaderValue::from_static("bytes"),
    );
    
    // ETag: "4483899d01fdc1:0"
    headers.insert(
        HeaderName::from_static("etag"),
        HeaderValue::from_static("\"4483899d01fdc1:0\""),
    );
    
    // Server: Microsoft-IIS/10.0
    headers.insert(
        HeaderName::from_static("server"),
        HeaderValue::from_static("Microsoft-IIS/10.0"),
    );
    
    // X-Powered-By: ASP.NET
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("ASP.NET"),
    );
    
    // Date: Wed, 07 Jan 2026 13:08:00 GMT
    headers.insert(
        HeaderName::from_static("date"),
        HeaderValue::from_static("Wed, 07 Jan 2026 13:08:00 GMT"),
    );
    
    // Content-Length: 16397
    headers.insert(
        HeaderName::from_static("content-length"),
        HeaderValue::from_static("16397"),
    );
    
    headers
}

/// 获取测试用的目标URL数组
#[allow(dead_code)]
pub fn get_test_urls() -> &'static [&'static str] {
    &["https://example.com/", "https://test.iis.com/", "https://demo.asp.net/"]
}

/// 获取测试用的HTML响应体
/// 修复：使用r##"..."## 分隔符，避免#!符号的语法冲突
#[allow(dead_code)]
pub fn get_test_html_body() -> &'static str {
    // 关键修复：将 r#"..."# 升级为 r##"..."##，支持包含#!的字符串
    r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>360网神数据脱敏系统</title>
</head>
<body>
    <div id="app">
        <header class="topbar">
            <a href="#!/home" class="sysname">360网神数据脱敏系统</a>
        </header>
        <div class="content">
            <p>欢迎使用数据脱敏系统</p>
        </div>
    </div>
</body>
</html>"##
}

/// 测试函数调用示例
#[allow(dead_code)]
fn test_data_usage() {
    let _headers = get_test_headers();
    let _urls = get_test_urls();
    let body = get_test_html_body();
    
    assert!(body.contains("#!/home")); // 验证特殊符号正常保留
    assert!(body.contains("360网神数据脱敏系统"));
}

#[allow(dead_code)]
fn main() {
    let html_body = get_test_html_body();
    println!("测试HTML内容：\n{}", html_body);
}