use crate::{
    ac_scanner::AcScanner,
    automation::cache::AcAutomatonCache,
    compiled::{CompiledBundle, LiteralId},
};
use rustc_hash::FxHashSet;

/// HTML维度证据快照：存储HTML/脚本/元标签的扫描结果
#[derive(Debug)]
pub struct HtmlEvidence<'a> {
    /// 原始HTML文本引用
    pub html: &'a str,
    /// 合并后的脚本源字符串引用
    pub script_src: &'a str,
    /// 元标签列表引用 (name, content)
    pub meta_tags: &'a Vec<(String, String)>,

    // 原始未转换的匹配结果
    /// 剪枝层 - Literal类型匹配结果（原始ID）
    pub literals_hit_ids: FxHashSet<LiteralId>,
    /// 剪枝层 - Any类型匹配结果（原始值ID）
    pub any_hit_ids: FxHashSet<LiteralId>,
    /// 匹配层 - Contains类型匹配结果（原始值ID）
    pub contains_hit_ids: FxHashSet<LiteralId>,
}

impl<'a> HtmlEvidence<'a> {
    #[inline(always)]
    pub fn build(
        html_safe_str: &'a str,
        script_src_combined: &'a str,
        meta_tags: &'a Vec<(String, String)>,
        ac_cache: &AcAutomatonCache,
        bundle: &CompiledBundle,
    ) -> Self {
        // 初始化ID集合
        let mut literals_hit_ids = FxHashSet::default();
        let mut any_hit_ids = FxHashSet::default();
        let mut contains_hit_ids = FxHashSet::default();

        // 扫描HTML（is_html=true）
        AcScanner::scan_and_classify_with_id(
            html_safe_str,
            &ac_cache.html_combined_ac,
            ac_cache,
            true,
            &mut literals_hit_ids,
            &mut any_hit_ids,
            &mut contains_hit_ids,
            bundle,
        );

        // 扫描脚本src
        AcScanner::scan_and_classify_with_id(
            script_src_combined,
            &ac_cache.html_combined_ac,
            ac_cache,
            true,
            &mut literals_hit_ids,
            &mut any_hit_ids,
            &mut contains_hit_ids,
            bundle,
        );

        // 扫描元标签
        let mut meta_combined = String::new();
        for (name, content) in meta_tags {
            meta_combined.push_str(name);
            meta_combined.push('\0'); // 分隔 name
            meta_combined.push_str(content);
            meta_combined.push('\0'); // 分隔 content
        }
        // 单次扫描拼接后的字符串，减少scan_and_classify_with_id调用次数
        // dbg!(&meta_tags);
        // dbg!(&meta_combined);
        AcScanner::scan_and_classify_with_id(
            &meta_combined,
            &ac_cache.html_combined_ac,
            ac_cache,
            true,
            &mut literals_hit_ids,
            &mut any_hit_ids,
            &mut contains_hit_ids,
            bundle,
        );

        Self {
            html: html_safe_str,
            script_src: script_src_combined,
            meta_tags,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
        }
    }
}
