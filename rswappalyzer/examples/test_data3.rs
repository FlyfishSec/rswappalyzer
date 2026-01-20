use http::header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use lol_html::{HtmlRewriter, RewriteStrSettings};

/// 获取服务器的测试响应头
#[allow(dead_code)]
pub fn get_test_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();

    // 1. server: FBCS
    headers.insert(
        HeaderName::from_static("server"),
        HeaderValue::from_static("SacaSnap/100"),
    );

    // 2. date: Mon, 19 Jan 2026 10:33:39 GMT
    headers.insert(
        HeaderName::from_static("date"),
        HeaderValue::from_static("Mon, 19 Jan 2026 10:33:39 GMT"),
    );

    // 3. content-type: text/html; charset=utf-8
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html; charset=utf-8"),
    );

    // 4. transfer-encoding: chunked
    headers.insert(
        HeaderName::from_static("transfer-encoding"),
        HeaderValue::from_static("chunked"),
    );

    // 5. connection: keep-alive
    headers.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("keep-alive"),
    );

    // 6. vary: Accept-Encoding (重复添加两次)
    headers.insert(
        HeaderName::from_static("vary"),
        HeaderValue::from_static("Accept-Encoding"),
    );
    headers.append(  // 重复的头使用 append 而不是 insert
        HeaderName::from_static("vary"),
        HeaderValue::from_static("Accept-Encoding"),
    );

    // 7. x-powered-by: PHP/8.3.9
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("PHP/8.3.9"),
    );

    // 8. set-cookie (第一个)
    headers.append(  // 多个 set-cookie 使用 append
        SET_COOKIE,
        HeaderValue::from_static("velink_lang=zh; expires=Mon, 19 Jan 2026 11:33:39 GMT; Max-Age=3600"),
    );

    // 9. set-cookie (第二个)
    headers.append(
        SET_COOKIE,
        // 注意转义双引号，使用 r#"..."# 原始字符串避免转义问题
        HeaderValue::from_static(r#"browser_fingerprint=bid_33737e350f3029a7e71a3cd33138f7666986ec9a9d3b56fafe5460ed0a2fd0ea; expires=Tue, 19 Jan 2027 10:33:39 GMT; Max-Age=31536000; path=/; domain=112.74.76.236:80; HttpOnly; SameSite=Lax"#),
    );

    // 10. access-control-allow-credentials: true
    headers.insert(
        HeaderName::from_static("access-control-allow-credentials"),
        HeaderValue::from_static("true"),
    );

    // 11. access-control-allow-methods: *
    headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("*"),
    );

    // 12. access-control-allow-headers: *
    headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("*"),
    );

    // 13. x-frame-options: SAMEORIGIN
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );

    // 14. x-content-type-options: nosniff
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // 15. referrer-policy: strict-origin-when-cross-origin
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // 16. permissions-policy: geolocation=(), microphone=(), camera=(), payment=()
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=()"),
    );

    headers
}

/// 获取测试用的目标URL数组
#[allow(dead_code)]
pub fn get_test_urls() -> &'static [&'static str] {
    &[
        "https://example.com/",
        "https://test.iis.com/",
        "https://demo.asp.net/",
    ]
}

/// 核心函数：读取HTML文件并通过lol_html完成标准化解析
/// 作用：确保返回的HTML是语法合法、结构完整的解析后内容
fn read_and_parse_html_file(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 步骤1：读取外部HTML文件原始内容
    let path = Path::new(file_path);
    eprintln!(
        "尝试读取的完整文件路径: {:?}",
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    );
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
        },
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
</html>"##
                .to_string()
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
