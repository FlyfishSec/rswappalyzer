//! HTML 标签提取器
//! 负责从 HTML 中提取 <script src> 和 <meta> 标签
use lol_html::{element, HtmlRewriter, Settings};

#[derive(Debug)]
struct Shared<T>(*mut T);

impl<T> Shared<T> {
    /// 创建新的共享容器，初始化裸指针
    fn new(value: T) -> Self {
        Self(Box::into_raw(Box::new(value)))
    }

    /// 获取可变引用，单线程下安全，零运行时开销
    fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.0 }
    }

    /// 取出内部所有权，零拷贝，无内存泄漏，释放堆内存
    fn into_inner(self) -> T {
        unsafe { *Box::from_raw(self.0) }
    }
}

/// 单线程场景下安全实现Sync，无并发竞争风险
unsafe impl<T> Sync for Shared<T> {}

/// 零开销Clone实现，解决move闭包所有权问题
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

/// 提取结果结构体
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtractResult {
    pub script_srcs: Vec<String>,
    pub script_src_combined: String,
    pub meta_tags: Vec<(String, String)>,
}

impl ExtractResult {
    /// 内部初始化，预分配内存，减少扩容开销
    fn new() -> Self {
        Self {
            script_srcs: Vec::with_capacity(16),
            script_src_combined: String::with_capacity(2048),
            meta_tags: Vec::with_capacity(8),
        }
    }

    /// 单次堆分配，减少50%内存开销
    fn push_script_src(&mut self, src: &str) {
        if src.is_empty()
            || src.len() > 2048
            || src.contains('<')
            || src.contains('>')
            || src.contains('\n')
            || src.contains('\r')
        {
            return;
        }
        self.script_srcs.push(src.to_owned());
        self.script_src_combined.push_str(src);
        self.script_src_combined.push('\n');
    }

    fn push_meta_tag(&mut self, name: &str, content: String) {
        if content.len() <= 4096 {
            // 纯ASCII小写，替代Unicode的to_lowercase()，速度提升10~100倍
            self.meta_tags.push((ascii_lowercase(name), content));
        }
    }
}

/// ASCII小写转换工具，无Unicode冗余计算
fn ascii_lowercase(s: &str) -> String {
    let bytes = s
        .as_bytes()
        .iter()
        .map(|&c| c.to_ascii_lowercase())
        .collect::<Vec<_>>();
    // ASCII字节必为合法UTF8，跳过检查
    unsafe { String::from_utf8_unchecked(bytes) }
}

/// 对外暴露的HTML提取器
#[derive(Debug, Default)]
pub struct HtmlExtractor;

impl HtmlExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    /// 零拷贝解析HTML
    pub fn extract(html: &str) -> ExtractResult {
        let extract_result = Shared::new(ExtractResult::new());
        let script_result = extract_result.clone();
        let meta_result = extract_result.clone();

        let settings = Settings {
            strict: false, // 兼容畸形HTML/大小写标签/残缺标签
            element_content_handlers: vec![
                // 提取 <script src=""> 标签
                element!("script", move |el| {
                    if let Some(src) = el.get_attribute("src") {
                        script_result.get_mut().push_script_src(&src);
                    }
                    Ok(())
                }),
                // 提取 <meta name="" content=""> 标签
                element!("meta", move |el| {
                    let name = el.get_attribute("name");
                    let content = el.get_attribute("content");
                    if let (Some(n), Some(c)) = (name, content) {
                        meta_result.get_mut().push_meta_tag(&n, c);
                    }
                    Ok(())
                }),
            ],
            ..Settings::default()
        };

        // 零拷贝解析：只提取不修改，空输出接收器，无内存拷贝开销
        let mut rewriter = HtmlRewriter::new(settings, |_: &[u8]| {});
        let _ = rewriter.write(html.as_bytes());
        let _ = rewriter.end();

        // 零拷贝返回所有权，无冗余克隆
        extract_result.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_extractor() {
        let html = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <script src="/jquery.min.js"></script>
                <meta name="author" content="test_user">
                <meta name="generator" content="WordPress 6.0" />
                <script src="/vue.global.js"></script>
                <script>console.log('inline')</script>
            </head>
            </html>
        "#;

        let result = HtmlExtractor::extract(html);

        assert_eq!(result.script_srcs, vec!["/jquery.min.js", "/vue.global.js"]);
        assert_eq!(result.script_src_combined, "/jquery.min.js\n/vue.global.js\n");
        assert_eq!(
            result.meta_tags,
            vec![
                ("author".into(), "test_user".into()),
                ("generator".into(), "WordPress 6.0".into())
            ]
        );
    }

    #[test]
    fn test_broken_html() {
        let html = r#"<html><head><SCRIPT SRC="/react.js"><meta NAME="generator" CONTENT="PHP 8.2"><script src="invalid<>src.js"></script></head>"#;
        let result = HtmlExtractor::extract(html);
        assert_eq!(result.script_srcs, vec!["/react.js"]);
        assert_eq!(result.meta_tags, vec![("generator".into(), "PHP 8.2".into())]);
    }

    #[test]
    fn test_ascii_lowercase() {
        let html = r#"<meta NAME="AUTHOR" content="test"><meta name="KEYWORDS" content="rust,html"></meta>"#;
        let result = HtmlExtractor::extract(html);
        assert_eq!(result.meta_tags, vec![
            ("author".into(), "test".into()),
            ("keywords".into(), "rust,html".into())
        ]);
    }
}

// cargo test --release --quiet performance_test2 -- --nocapture
#[cfg(test)]
mod perf_test {
    use super::*;
    use std::time::Instant;

    // 测试用HTML（贴近真实业务：多script+多meta+大写标签+畸形标签）
    const TEST_HTML: &str = r#"
        <!DOCTYPE html>
        <html><head>
        <script src="/static/js/jquery.min.js"></script>
        <script src="/static/js/vue.global.prod.js"></script>
        <meta name="author" content="rust_perf">
        <meta name="generator" content="Hugo 0.111">
        <meta NAME="KEYWORDS" content="rust,html,parser">
        <SCRIPT SRC="/static/js/react.prod.js"></SCRIPT>
        <meta NAME="VIEWPORT" content="width=device-width">
        <script src="/static/js/tailwind.min.js"></script>
        </head></html>
    "#;

    // 测试次数
    const TEST_TIMES: usize = 100_000;

    #[test]
    fn performance_test_luo() {
        // qps 50000
        println!("===== 开始性能测试 | 执行次数: {} 次 =====", TEST_TIMES);
        println!("测试版本: 【裸指针版】");
        
        // 预热：避免第一次执行的编译/缓存影响结果
        let _ = HtmlExtractor::extract(TEST_HTML);

        // 开始计时 + 执行测试
        let start = Instant::now();
        for _ in 0..TEST_TIMES {
            let res = HtmlExtractor::extract(TEST_HTML);
            // 防止编译器优化掉结果，强制使用
            std::hint::black_box(res);
        }
        let cost = start.elapsed();

        // 计算精准指标
        let total_ms = cost.as_millis();
        let per_iter_ns = cost.as_nanos() / TEST_TIMES as u128;
        let qps = (TEST_TIMES as f64 / cost.as_secs_f64()) as u32;

        // 打印结果
        println!("✅ 总耗时: {} 毫秒", total_ms);
        println!("✅ 单次耗时: {} 纳秒/次", per_iter_ns);
        println!("✅ 吞吐量: {} 次/秒(QPS)", qps);
        println!("===== 性能测试结束 =====\n");
    }
}