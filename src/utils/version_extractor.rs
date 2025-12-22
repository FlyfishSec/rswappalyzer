//! 版本提取工具模块
//! 负责从正则捕获结果中，根据版本模板提取合法的技术版本号
//! 支持 \1/\2 或 $1/$2 两种分组引用格式，自动过滤无效版本

use regex::Captures;

/// 版本提取工具类
/// 提供静态方法 `extract` 用于版本号提取
pub struct VersionExtractor;

impl VersionExtractor {
    /// 从正则捕获结果中提取有效版本号
    ///
    /// # 参数
    /// - `version_template`: 版本模板（可选字符串），支持 \1/\2 或 $1/$2 分组引用
    /// - `captures`: 正则捕获结果，包含整体匹配和自定义分组匹配信息
    ///
    /// # 返回值
    /// - `Some(String)`: 提取到的有效版本号
    /// - `None`: 未提取到有效版本（模板无效/未替换/版本异常）
    ///
    /// # 功能特性
    /// 1. 兼容 \1/\2 和 $1/$2 两种分组引用格式
    /// 2. 自动清理分组值和最终版本的前后空白字符
    /// 3. 多条件过滤无效版本，避免返回异常值
    pub fn extract(version_template: &Option<String>, captures: &Captures) -> Option<String> {
        // 1. 前置过滤：排除 None 模板 和 空白模板，减少无效计算
        version_template
            .as_ref()
            .filter(|template| !template.trim().is_empty())
            .and_then(|template| {
                // 2. 初始化版本字符串（克隆模板，避免修改原始模板）
                let mut version = template.clone();
                // 标记是否发生过有效的分组替换（避免无替换却返回模板本身）
                let mut replaced = false;

                // 3. 遍历所有自定义捕获分组（从 1 开始，0 是整体匹配，不参与版本提取）
                for group_index in 1..captures.len() {
                    // 预生成两种分组占位符，避免循环内重复格式化，提升性能
                    let placeholder_backslash = format!("\\{}", group_index); // \1 格式
                    let placeholder_dollar = format!("${}", group_index);      // $1 格式

                    // 获取当前分组的匹配内容
                    if let Some(matched) = captures.get(group_index) {
                        // 清理分组值前后空白，避免将无效空白带入最终版本
                        let matched_str = matched.as_str().trim();
                        // 替换模板中的对应占位符（同时兼容两种格式）
                        version = version.replace(&placeholder_backslash, matched_str);
                        version = version.replace(&placeholder_dollar, matched_str);
                        // 标记已发生有效替换
                        replaced = true;
                    } else {
                        // 分组不存在时，也替换占位符为空白
                        version = version.replace(&placeholder_backslash, "");
                        version = version.replace(&placeholder_dollar, "");
                    }
                }

                // 4. 最终版本清理：去除整体前后空白，确保版本格式规范
                let final_version = version.trim().to_string();

                // 5. 无效版本过滤（短路判断，提升性能）
                // 过滤条件：未发生替换 / 版本为空 / 残留 \ 占位符 / 残留 $ 占位符
                let is_valid_version = !(!replaced || final_version.is_empty() || final_version.contains('\\') || final_version.contains('$'));

                // 6. 返回有效版本或 None
                if is_valid_version {
                    Some(final_version)
                } else {
                    None
                }
            })
    }
}

// 单元测试
#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn test_extract_valid_version_with_backslash_placeholder() {
        // 测试场景：\1 格式占位符，有效分组值
        let regex = Regex::new(r#"nginx(?:/([\d.]+))?"#).unwrap();
        let captures = regex.captures("nginx/1.21.6").unwrap();
        let template = Some("\\1".to_string());

        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, Some("1.21.6".to_string()));
    }

    #[test]
    fn test_extract_valid_version_with_dollar_placeholder() {
        // 测试场景：$1 格式占位符，有效分组值
        let regex = Regex::new(r#"apache(?:/([\d.]+))?"#).unwrap();
        let captures = regex.captures("apache/2.4.57").unwrap();
        let template = Some("$1".to_string());

        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, Some("2.4.57".to_string()));
    }

    #[test]
    fn test_extract_empty_group_version() {
        // 测试场景：分组存在但值为空，应返回 None
        let regex = Regex::new(r#"nginx(?:/([\d.]+))?"#).unwrap();
        let captures = regex.captures("nginx").unwrap();
        let template = Some("\\1".to_string());

        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, None);
    }

    #[test]
    fn test_extract_invalid_placeholder_version() {
        // 测试场景：占位符不存在（\2），应返回 None
        let regex = Regex::new(r#"nginx(?:/([\d.]+))?"#).unwrap();
        let captures = regex.captures("nginx/1.21.6").unwrap();
        let template = Some("\\2".to_string());

        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, None);
    }

    #[test]
    fn test_extract_complex_template_version() {
        // 测试场景：多分组复杂模板，应正常提取
        let regex = Regex::new(r#"(\w+)/v([\d.]+)-(\w+)"#).unwrap();
        let captures = regex.captures("rust/v1.75.0-stable").unwrap();
        let template = Some("\\1-$2-\\3".to_string());

        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, Some("rust-1.75.0-stable".to_string()));
    }

    #[test]
    fn test_extract_template_with_whitespace() {
        // 测试场景：模板带空白，应自动清理
        // 正则添加 \s*（匹配任意空格）：允许版本号前后有空格
        let regex = Regex::new(r#"nginx(?:/\s*([\d.]+)\s*)?"#).unwrap();
        let captures = regex.captures("nginx/ 1.21.6 ").unwrap(); // 保留空格
        let template = Some("  \\1  ".to_string());
    
        let version = VersionExtractor::extract(&template, &captures);
        assert_eq!(version, Some("1.21.6".to_string()));
    }
}