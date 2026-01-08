// examples/test_data.rs
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
    
    // 修正：Date字段时间戳和实际响应头一致
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

/// 获取测试用的目标URL数组（原有）
#[allow(dead_code)]
pub fn get_test_urls() -> &'static [&'static str] {
    &["https://example.com/"]
}

/// 获取测试用的HTML响应体
#[allow(dead_code)]
pub fn get_test_html_body() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">　
</script>"#
}

#[allow(dead_code)]
fn main() {}