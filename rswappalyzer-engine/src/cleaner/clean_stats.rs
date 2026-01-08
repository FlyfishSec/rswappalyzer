//! 负责统计数据的定义、更新与格式化输出

/// 规则清理统计信息
/// 记录规则清理过程中的各类指标：
/// 1. 技术规则总数/保留数/丢弃数
/// 2. 各类型模式（URL/HTML/Script等）的原始数/有效数
/// 3. 匹配类型分布（StartsWith/Contains/Regex）
/// 4. 正则修复统计（无效转义/字符集问题/分组问题等）
#[derive(Debug, Default)]
pub struct CleanStats {
    // ========== 技术规则统计 ==========
    /// 原始技术规则总数
    pub total_original_tech_rules: u32,
    /// 保留的有效技术规则数
    pub kept_tech_rules: u32,
    /// 丢弃的无效技术规则数
    pub discarded_tech_rules: u32,

    // ========== 模式数量统计 ==========
    /// URL模式原始数量
    pub original_url_patterns: u32,
    /// URL模式有效数量
    pub valid_url_patterns: u32,
    /// HTML模式原始数量
    pub original_html_patterns: u32,
    /// HTML模式有效数量
    pub valid_html_patterns: u32,
    /// Script模式原始数量
    pub original_script_patterns: u32,
    /// Script模式有效数量
    pub valid_script_patterns: u32,
    /// Header模式原始数量
    pub original_header_patterns: u32,
    /// Header模式有效数量
    pub valid_header_patterns: u32,
    /// Meta模式原始数量
    pub original_meta_patterns: u32,
    /// Meta模式有效数量
    pub valid_meta_patterns: u32,

    // ========== 匹配类型统计 ==========
    /// Contains匹配类型数量
    pub contains_count: u32,
    /// Regex匹配类型数量
    pub regex_count: u32,
    /// 无效正则总数（已剔除）
    pub invalid_regex_total: u32,

    // ========== 正则修复统计 ==========
    /// 正则修复总数（各类型修复之和）
    pub fixed_regex_total_count: u32,
    /// 修复无效转义的正则数量
    pub fixed_invalid_escapes_count: u32,
    /// 修复字符集连字符的正则数量
    pub fixed_charset_hyphen_count: u32,
    /// 修复未闭合分组的正则数量
    pub fixed_unbalanced_groups_count: u32,
    /// 修复无效字符集的正则数量
    pub fixed_invalid_charset_count: u32,
}

impl CleanStats {
    /// 更新原始模式数量统计
    /// 参数：
    /// - pattern_type: 模式类型（url/html/script/header/meta）
    /// - count: 新增数量（usize转u32）
    pub fn update_original_pattern_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        match pattern_type.to_lowercase().as_str() {
            "url" => self.original_url_patterns += count,
            "html" => self.original_html_patterns += count,
            "script" => self.original_script_patterns += count,
            "header" => self.original_header_patterns += count,
            "meta" => self.original_meta_patterns += count,
            _ => log::trace!("Unknown pattern type for original stats: {}", pattern_type),
        }
    }

    /// 更新有效模式数量统计
    /// 参数：
    /// - pattern_type: 模式类型（url/html/script/header/meta）
    /// - count: 新增有效数量（usize转u32）
    pub fn update_valid_pattern_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        match pattern_type.to_lowercase().as_str() {
            "url" => self.valid_url_patterns += count,
            "html" => self.valid_html_patterns += count,
            "script" => self.valid_script_patterns += count,
            "header" => self.valid_header_patterns += count,
            "meta" => self.valid_meta_patterns += count,
            _ => log::trace!("Unknown pattern type for valid stats: {}", pattern_type),
        }
    }

    /// 更新无效正则数量统计（剔除无效正则）
    /// 功能：
    /// 1. 累加无效正则总数
    /// 2. 从对应模式的原始数量中扣除（saturating_sub避免下溢）
    /// 参数：
    /// - pattern_type: 模式类型（url/html/script/header/meta）
    /// - count: 无效正则数量（usize转u32）
    pub fn update_invalid_regex_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        self.invalid_regex_total += count;
        
        match pattern_type.to_lowercase().as_str() {
            "url" => self.original_url_patterns = self.original_url_patterns.saturating_sub(count),
            "html" => self.original_html_patterns = self.original_html_patterns.saturating_sub(count),
            "script" => self.original_script_patterns = self.original_script_patterns.saturating_sub(count),
            "header" => self.original_header_patterns = self.original_header_patterns.saturating_sub(count),
            "meta" => self.original_meta_patterns = self.original_meta_patterns.saturating_sub(count),
            _ => log::trace!("Unknown pattern type for invalid regex stats: {}", pattern_type),
        }
    }

    /// 更新修复统计总数（汇总各类型修复数量）
    /// 调用时机：所有修复统计更新完成后调用
    pub fn update_fixed_stats(&mut self) {
        self.fixed_regex_total_count = self.fixed_invalid_escapes_count
            + self.fixed_charset_hyphen_count
            + self.fixed_unbalanced_groups_count
            + self.fixed_invalid_charset_count;
    }

    /// 格式化输出统计信息（结构化日志）
    /// 参数：total_time - 规则清理总耗时
    pub fn print_stats(&self, total_time: std::time::Duration) {
        // 基础规则统计
        log::debug!(
            "Rule cleaning completed | Time: {:?} | Original rules: {} | Kept rules: {} | Discarded rules: {}",
            total_time,
            self.total_original_tech_rules,
            self.kept_tech_rules,
            self.discarded_tech_rules
        );
        
        // 模式数量统计
        log::debug!(
            "Pattern stats: URL (original {} -> valid {}) | HTML (original {} -> valid {}) | Script (original {} -> valid {}) | Header (original {} -> valid {}) | Meta (original {} -> valid {})",
            self.original_url_patterns,
            self.valid_url_patterns,
            self.original_html_patterns,
            self.valid_html_patterns,
            self.original_script_patterns,
            self.valid_script_patterns,
            self.original_header_patterns,
            self.valid_header_patterns,
            self.original_meta_patterns,
            self.valid_meta_patterns
        );
        
        // 匹配类型统计
        log::debug!(
            "Match type stats: Contains {} | Regex {} | Invalid regex removed {}",
            self.contains_count,
            self.regex_count,
            self.invalid_regex_total
        );
        
        // 正则修复统计
        log::debug!(
            "Regex fix stats: Total {} (invalid escapes {} | charset hyphen {} | unbalanced groups {} | invalid charset {})",
            self.fixed_regex_total_count,
            self.fixed_invalid_escapes_count,
            self.fixed_charset_hyphen_count,
            self.fixed_unbalanced_groups_count,
            self.fixed_invalid_charset_count
        );
    }
}