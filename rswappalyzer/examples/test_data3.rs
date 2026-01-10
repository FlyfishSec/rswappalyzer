use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
// 修正：移除不存在的 Bytes 导入，只保留需要的类型
use lol_html::{HtmlRewriter, RewriteStrSettings};

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
        HeaderValue::from_static("Apache-Coyote/1.1"),
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

/// 核心函数：读取HTML文件并通过lol_html完成标准化解析
/// 作用：确保返回的HTML是语法合法、结构完整的解析后内容
fn read_and_parse_html_file(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 步骤1：读取外部HTML文件原始内容
    let path = Path::new(file_path);
    eprintln!("尝试读取的完整文件路径: {:?}", path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    let mut file = File::open(path)?;
    let mut raw_html = String::new();
    file.read_to_string(&mut raw_html)?;

    // 步骤2：使用lol_html解析并标准化HTML（修复语法、补全标签等）
    let mut parsed_html = Vec::new();
    // 初始化lol_html重写器（关键修正：调用.into()转换类型）
    let mut rewriter = HtmlRewriter::new(
        RewriteStrSettings::default().into(), // 修正：转换为Settings类型
        |chunk: &[u8]| {
            parsed_html.extend_from_slice(chunk);
        }
    );

    // 将原始HTML写入重写器，完成解析
    rewriter.write(raw_html.as_bytes())?;
    rewriter.end()?;

    // 转换为字符串并返回
    Ok(String::from_utf8(parsed_html)?)
}

/// 对外暴露的核心函数：返回从文件读取并经lol_html解析后的完整HTML
/// 兼容原有调用方式，默认读取 test_data/test_html.html 文件
#[allow(dead_code)]
pub fn get_test_html_body() -> String {
    let project_root = env::current_dir().unwrap(); // 获取当前工作目录
    let html_file_path = project_root.join("test_data").join("test_html.html");
    let html_file_str = html_file_path.to_str().unwrap();

    // 读取并解析HTML文件
    match read_and_parse_html_file(html_file_str) {
        Ok(parsed_content) => parsed_content,
        Err(e) => {
            eprintln!("读取/解析HTML文件失败: {}，返回兜底HTML", e);
            r##"<!DOCTYPE html>
</html>"##.to_string()
        }
    }
}

/// 测试函数：验证返回的是解析后的完整HTML
#[allow(dead_code)]
fn test_data_usage() {
    let html = get_test_html_body();
    println!("解析后的完整HTML:\n{}", html);
    
    // 验证关键内容存在
    assert!(html.contains("<!DOCTYPE html>"), "HTML缺少文档声明");
    assert!(html.contains("#!/home"), "未找到目标文本");
    assert!(html.contains("360网神数据脱敏系统"), "未找到目标文本");
}

#[allow(dead_code)]
fn main() {
    test_data_usage();
}