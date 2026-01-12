use aho_corasick::AhoCorasick;
use rustc_hash::FxHashSet;

// 核心：输入证据快照（一次扫描，全量结果，仅在detect生命周期内有效）
#[derive(Debug)]
pub struct HtmlEvidence<'a> {
    pub html: &'a str,
    pub script_src: &'a str,
    pub meta_tags: &'a Vec<(String, String)>,

    // 结果字段（由外部填充）
    pub html_tokens: FxHashSet<String>,
    pub literals_hit: FxHashSet<&'a str>,
    pub any_hit: FxHashSet<&'a str>,
}

impl<'a> HtmlEvidence<'a> {
    /// 构建证据快照
    #[inline(always)]
    pub fn build(
        html_safe_str: &'a str,
        script_src_combined: &'a str,
        meta_tags: &'a Vec<(String, String)>,
        ac_literal: &AhoCorasick, // 从runtime_lib取全局AC
        ac_any: &AhoCorasick,
        html_tokens: FxHashSet<String>,
    ) -> Self {
        // 2. AC扫描literal（只扫一次HTML，存所有命中结果）
        let mut literals_hit = FxHashSet::default();
        for mat in ac_literal.find_iter(html_safe_str) {
            // 使用范围截取替代 as_str() 方法
            let lit = &html_safe_str[mat.start()..mat.end()];
            literals_hit.insert(lit);
        }

        // 3. AC扫描any（只扫一次HTML，存所有命中结果）
        let mut any_hit = FxHashSet::default();
        for mat in ac_any.find_iter(html_safe_str) {
            // 使用范围截取替代 as_str() 方法
            let any = &html_safe_str[mat.start()..mat.end()];
            any_hit.insert(any);
        }

        Self {
            html: html_safe_str,
            script_src: script_src_combined,
            meta_tags,
            literals_hit,
            any_hit,
            html_tokens,
        }
    }
}
