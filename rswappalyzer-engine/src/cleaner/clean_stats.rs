//! 负责统计数据的定义、更新与格式化输出

/// 规则清理统计信息
#[derive(Debug, Default)]
pub struct CleanStats {
    // 技术规则统计
    pub total_original_tech_rules: u32,
    pub kept_tech_rules: u32,
    pub discarded_tech_rules: u32,

    // 模式数量统计
    pub original_url_patterns: u32,
    pub valid_url_patterns: u32,
    pub original_html_patterns: u32,
    pub valid_html_patterns: u32,
    pub original_script_patterns: u32,
    pub valid_script_patterns: u32,
    pub original_header_patterns: u32,
    pub valid_header_patterns: u32,
    pub original_meta_patterns: u32,
    pub valid_meta_patterns: u32,

    // 匹配类型统计
    pub starts_with_count: u32,
    pub contains_count: u32,
    pub regex_count: u32,
    pub invalid_regex_total: u32,

    // 正则修复统计
    pub fixed_regex_total_count: u32,
    pub fixed_invalid_escapes_count: u32,
    pub fixed_charset_hyphen_count: u32,
    pub fixed_unbalanced_groups_count: u32,
    pub fixed_invalid_charset_count: u32,
}

impl CleanStats {
    /// 更新原始模式数量统计
    pub fn update_original_pattern_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        match pattern_type {
            "url" => self.original_url_patterns += count,
            "html" => self.original_html_patterns += count,
            "script" => self.original_script_patterns += count,
            "header" => self.original_header_patterns += count,
            "meta" => self.original_meta_patterns += count,
            _ => {}
        }
    }

    /// 更新有效模式数量统计
    pub fn update_valid_pattern_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        match pattern_type {
            "url" => self.valid_url_patterns += count,
            "html" => self.valid_html_patterns += count,
            "script" => self.valid_script_patterns += count,
            "header" => self.valid_header_patterns += count,
            "meta" => self.valid_meta_patterns += count,
            _ => {}
        }
    }

    /// 更新无效正则数量统计
    pub fn update_invalid_regex_stats(&mut self, pattern_type: &str, count: usize) {
        let count = count as u32;
        self.invalid_regex_total += count;
        match pattern_type {
            "url" => self.original_url_patterns = self.original_url_patterns.saturating_sub(count),
            "html" => self.original_html_patterns = self.original_html_patterns.saturating_sub(count),
            "script" => self.original_script_patterns = self.original_script_patterns.saturating_sub(count),
            "header" => self.original_header_patterns = self.original_header_patterns.saturating_sub(count),
            "meta" => self.original_meta_patterns = self.original_meta_patterns.saturating_sub(count),
            _ => {}
        }
    }

    /// 更新修复统计总数
    pub fn update_fixed_stats(&mut self) {
        self.fixed_regex_total_count = self.fixed_invalid_escapes_count
            + self.fixed_charset_hyphen_count
            + self.fixed_unbalanced_groups_count
            + self.fixed_invalid_charset_count;
    }

    /// 格式化输出统计信息
    pub fn print_stats(&self, total_time: std::time::Duration) {
        println!(
            "规则清理+预处理完成 | 耗时 {:?} | 原始规则数 {} | 保留有效规则数 {} | 丢弃无效规则数 {}",
            total_time,
            self.total_original_tech_rules,
            self.kept_tech_rules,
            self.discarded_tech_rules
        );
        println!(
            "模式统计：URL（原始 {} -> 有效 {}） | HTML（原始 {} -> 有效 {}） | Script（原始 {} -> 有效 {}） | Header（原始 {} -> 有效 {}） | Meta（原始 {} -> 有效 {}）",
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
        println!(
            "匹配类型统计：StartsWith {} | Contains {} | Regex {} | 无效正则剔除 {}",
            self.starts_with_count,
            self.contains_count,
            self.regex_count,
            self.invalid_regex_total
        );
        println!(
            "正则修复：总 {} (无效转义 {} | 字符集连字符 {} | 未闭合分组 {} | 无效字符集 {})",
            self.fixed_regex_total_count,
            self.fixed_invalid_escapes_count,
            self.fixed_charset_hyphen_count,
            self.fixed_unbalanced_groups_count,
            self.fixed_invalid_charset_count
        );
    }
}