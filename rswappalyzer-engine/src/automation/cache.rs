use crate::{
    compiled::{CompiledBundle, LiteralId},
    error::CoreResult,
    pattern_kind::PatternKind,
    CompiledRuleLibrary, Scope,
};
use aho_corasick::{
    AhoCorasick, AhoCorasickBuilder, BuildError, MatchKind, PatternID, PatternIDError,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::fmt;

/// AC自动机缓存
#[derive(Debug)]
pub struct AcAutomatonCache {
    /// HTML维度组合AC自动机（包含Literal/Any/Contains所有规则）
    pub html_combined_ac: AhoCorasick,
    /// HTML维度：LiteralId → 所属所有PatternKind（替代原str_to_all_kinds）
    pub html_id_to_all_kinds: FxHashMap<LiteralId, FxHashSet<PatternKind>>,
    /// 反向映射：AC PatternID → LiteralId（AC匹配结果关联到业务ID）
    pub html_pattern_id_to_lit_id: Vec<LiteralId>,

    /// Header维度组合AC自动机
    pub header_combined_ac: AhoCorasick,
    /// Header维度：LiteralId → 所属所有PatternKind
    pub header_id_to_all_kinds: FxHashMap<LiteralId, FxHashSet<PatternKind>>,
    /// 反向映射：AC PatternID → LiteralId
    pub header_pattern_id_to_lit_id: Vec<LiteralId>,
}

/// AC自动机扫描错误类型
#[derive(Debug)]
pub enum AcScanError {
    PatternIDError(PatternIDError),
    BuildError(BuildError),
}

impl fmt::Display for AcScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcScanError::PatternIDError(e) => write!(f, "PatternID创建失败: {}", e),
            AcScanError::BuildError(e) => write!(f, "AC构建失败: {}", e),
        }
    }
}

impl std::error::Error for AcScanError {}

// 转换BuildError到AcScanError
impl From<BuildError> for AcScanError {
    fn from(e: BuildError) -> Self {
        AcScanError::BuildError(e)
    }
}

impl AcAutomatonCache {
    /// 创建AC自动机缓存实例（适配CompiledBundle）
    pub fn new(bundle: &CompiledBundle) -> CoreResult<Self> {
        // 构建HTML维度AC + ID映射
        let (html_combined_ac, html_id_to_all_kinds, html_pattern_id_to_lit_id) =
            Self::build_combined_ac_with_id_mapping(
                bundle,
                &[Scope::Html, Scope::Meta, Scope::Script],
            )?;

        // 构建Header维度AC + ID映射
        let (header_combined_ac, header_id_to_all_kinds, header_pattern_id_to_lit_id) =
            Self::build_combined_ac_with_id_mapping(bundle, &[Scope::Header, Scope::Cookie])?;

        Ok(Self {
            html_combined_ac,
            html_id_to_all_kinds,
            html_pattern_id_to_lit_id,
            header_combined_ac,
            header_id_to_all_kinds,
            header_pattern_id_to_lit_id,
        })
    }

    /// 构建指定作用域的组合AC自动机及ID分类映射
    fn build_combined_ac_with_id_mapping(
        bundle: &CompiledBundle,
        scopes: &[Scope],
    ) -> CoreResult<(
        AhoCorasick,
        FxHashMap<LiteralId, FxHashSet<PatternKind>>,
        Vec<LiteralId>,
    )> {
        // ========== 步骤1：聚合ID + 构建ID→PatternKind映射 ==========
        let mut id_to_all_kinds = FxHashMap::default();
        let mut all_lit_ids = Vec::new();

        // 聚合Literal类型
        Self::aggregate_id_with_kind(
            bundle,
            scopes,
            PatternKind::Literal,
            &mut id_to_all_kinds,
            &mut all_lit_ids,
            |lib, scope| lib.known_literals_by_scope.get(scope),
        );

        // 聚合Any类型
        Self::aggregate_id_with_kind(
            bundle,
            scopes,
            PatternKind::Any,
            &mut id_to_all_kinds,
            &mut all_lit_ids,
            |lib, scope| lib.known_any_by_scope.get(scope),
        );

        // 聚合Contains类型
        Self::aggregate_id_with_kind(
            bundle,
            scopes,
            PatternKind::Contains,
            &mut id_to_all_kinds,
            &mut all_lit_ids,
            |lib, scope| lib.known_contains_by_scope.get(scope),
        );

        // ========== 步骤2：ID去重==========
        let mut unique_lit_ids = FxHashSet::default();
        let mut deduped_lit_ids = Vec::new();
        for &lit_id in &all_lit_ids {
            if unique_lit_ids.insert(lit_id) {
                deduped_lit_ids.push(lit_id);
            }
        }

        // ========== 步骤3：统计重复信息 ==========
        // let total_patterns = all_lit_ids.len();
        // let unique_patterns = deduped_lit_ids.len();
        // let duplicate_count = total_patterns - unique_patterns;
        // let duplicate_rate = if total_patterns > 0 {
        //     (duplicate_count as f64 / total_patterns as f64) * 100.0
        // } else {
        //     0.0
        // };

        // // 统计高频重复ID
        // let mut id_count = FxHashMap::default();
        // for &lit_id in &all_lit_ids {
        //     *id_count.entry(lit_id).or_insert(0) += 1;
        // }
        // let mut high_freq_duplicates: Vec<_> = id_count
        //     .into_iter()
        //     .filter(|(_, count)| *count >= 2)
        //     .map(|(lit_id, count)| {
        //         // 从映射池获取字符串用于打印
        //         let lit_str = bundle.get_literal(lit_id).unwrap_or("UNKNOWN");
        //         (lit_str.to_string(), count)
        //     })
        //     .collect();
        // high_freq_duplicates.sort_by(|a, b| b.1.cmp(&a.1));

        // // 打印统计结果
        // println!("=====================================");
        // println!("[Pattern重复统计] scopes={:?}", scopes);
        // println!("总pattern数：{} 条", total_patterns);
        // println!("唯一pattern数：{} 条", unique_patterns);
        // println!("重复pattern数：{} 条（重复率：{:.2}%）", duplicate_count, duplicate_rate);
        // if !high_freq_duplicates.is_empty() {
        //     println!("[高频重复项 Top10]：");
        //     for (i, (pat, count)) in high_freq_duplicates.iter().take(10).enumerate() {
        //         println!("  {}. '{}' → 重复 {} 次", i + 1, pat, count);
        //     }
        // }
        // println!("=====================================");

        // ========== 步骤4：将ID转为字符串，构建AC自动机 ==========
        // 准备AC构建的字符串列表（从ID映射池获取）
        let pattern_strs: Vec<&str> = deduped_lit_ids
            .iter()
            .map(|&lit_id| bundle.get_literal(lit_id).unwrap())
            .collect();
        // 转换为字节切片
        let pattern_bytes: Vec<&[u8]> = pattern_strs.iter().map(|s| s.as_bytes()).collect();

        // 构建AC自动机
        //let ac_build_start = std::time::Instant::now();
        let combined_ac = AhoCorasickBuilder::new()
            //.ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&pattern_bytes)?;
        // let ac_build_duration = ac_build_start.elapsed();
        // println!(
        //     "[AC构建] scopes={:?}, 去重后规则数={} 条, 构建耗时：{} 毫秒（{} 纳秒）",
        //     &scopes,
        //     deduped_lit_ids.len(),
        //     ac_build_duration.as_millis(),
        //     ac_build_duration.as_nanos()
        // );

        // ========== 步骤5：构建AC PatternID → LiteralId的映射 ==========
        // AC的PatternID对应deduped_lit_ids的索引
        let pattern_id_to_lit_id = deduped_lit_ids.clone();

        Ok((combined_ac, id_to_all_kinds, pattern_id_to_lit_id))
    }

    /// 聚合指定类型的LiteralId并构建ID→PatternKind映射（统一逻辑）
    fn aggregate_id_with_kind<'a, F>(
        bundle: &'a CompiledBundle,
        scopes: &'a [Scope],
        kind: PatternKind,
        id_to_all_kinds: &mut FxHashMap<LiteralId, FxHashSet<PatternKind>>,
        all_lit_ids: &mut Vec<LiteralId>,
        getter: F,
    ) where
        F: Fn(&'a CompiledRuleLibrary, &'a Scope) -> Option<&'a FxHashSet<LiteralId>>,
    {
        let lib = &bundle.library;
        for scope in scopes {
            if let Some(scope_lit_ids) = getter(lib, scope) {
                for &lit_id in scope_lit_ids {
                    // 添加ID到列表（允许重复，后续去重）
                    all_lit_ids.push(lit_id);
                    // 更新ID→PatternKind映射（自动合并重复ID的类型）
                    id_to_all_kinds
                        .entry(lit_id)
                        .or_insert_with(FxHashSet::default)
                        .insert(kind);
                }
            }
        }
    }

    // ========== 运行时匹配结果适配（从AC PatternID到业务信息） ==========
    /// HTML维度：从AC匹配的PatternID获取LiteralId
    pub fn html_pattern_id_to_literal_id(&self, pattern_id: PatternID) -> Option<LiteralId> {
        self.html_pattern_id_to_lit_id
            .get(pattern_id.as_usize())
            .copied()
    }

    /// HTML维度：从LiteralId获取所属PatternKind
    pub fn html_get_pattern_kinds(&self, lit_id: LiteralId) -> Option<&FxHashSet<PatternKind>> {
        self.html_id_to_all_kinds.get(&lit_id)
    }

    /// Header维度：从AC PatternID获取LiteralId
    pub fn header_pattern_id_to_literal_id(&self, pattern_id: PatternID) -> Option<LiteralId> {
        self.header_pattern_id_to_lit_id
            .get(pattern_id.as_usize())
            .copied()
    }

    /// Header维度：从LiteralId获取所属PatternKind
    pub fn header_get_pattern_kinds(&self, lit_id: LiteralId) -> Option<&FxHashSet<PatternKind>> {
        self.header_id_to_all_kinds.get(&lit_id)
    }
}
