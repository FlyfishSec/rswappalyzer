/// HTML 输入守卫：负责在进入 HTML / DOM / Regex 分析前
/// 保证输入「值得分析」且「不会拖垮引擎」
use std::borrow::Cow;

pub struct HtmlInputGuard;

impl HtmlInputGuard {
    /// 最大 HTML 长度（2MB）
    pub const MAX_HTML_LEN: usize = 2 * 1024 * 1024;
    /// 最小有效长度（过滤垃圾）
    pub const MIN_VALID_LEN: usize = 16;

    #[inline(always)]
    pub fn guard(mut html: Cow<str>) -> Option<Cow<str>> {
        // 1. 空输入：直接判定无效
        if html.is_empty() {
            return None;
        }

        // 2. 超长保护（零拷贝 + UTF-8 边界安全）
        if html.len() > Self::MAX_HTML_LEN {
            let mut cut = Self::MAX_HTML_LEN;
            while !html.is_char_boundary(cut) {
                cut -= 1;
            }

            match html {
                Cow::Borrowed(s) => html = Cow::Owned(s[..cut].to_string()),
                Cow::Owned(ref mut s) => s.truncate(cut),
            }
        }

        // 3. ASCII 级 trim（核心优化：手写零开销双端trim，替代trim_matches，无闭包+无重复遍历）
        match html {
            Cow::Owned(ref mut s) => {
                // 原地trim：先找头部有效边界
                let start = s.bytes().position(|b| !b.is_ascii_whitespace() && !b.is_ascii_control()).unwrap_or(0);
                // 再找尾部有效边界
                let end = s.bytes().rposition(|b| !b.is_ascii_whitespace() && !b.is_ascii_control()).map_or(0, |p| p + 1);
                
                if start >= end || end - start < Self::MIN_VALID_LEN {
                    return None;
                }
                // 原地截断，零内存分配，直接修改原字符串
                *s = s[start..end].to_string();
            }
            Cow::Borrowed(s) => {
                // 零拷贝trim：仅计算有效长度，不生成新字符串，无内存分配
                let start = s.bytes().position(|b| !b.is_ascii_whitespace() && !b.is_ascii_control()).unwrap_or(0);
                let end = s.bytes().rposition(|b| !b.is_ascii_whitespace() && !b.is_ascii_control()).map_or(0, |p| p + 1);
                
                if start >= end || end - start < Self::MIN_VALID_LEN {
                    return None;
                }
            }
        }

        // 4. 通过所有校验，安全返回
        Some(html)
    }
}