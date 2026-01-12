use aho_corasick::AhoCorasick;
use rustc_hash::{FxHashMap, FxHashSet};


// 标准化Cookie结构体
#[derive(Debug, Clone)]
pub struct StandardCookie {
    pub name: String,       // Cookie名（小写）
    pub value: String,      // Cookie值
    pub source: String,     // 来源Header（"cookie"或"set-cookie"）
}


#[derive(Debug)]
pub struct HeaderEvidence<'a> {
    // 原始数据引用（零拷贝）
    pub header_map: &'a FxHashMap<String, String>,
    pub cookies: &'a [StandardCookie], // 标准化Cookie实体切片

    // Token提取结果
    pub header_tokens: FxHashSet<String>,

    // AC扫描结果（合并Header(key+value)+Cookie扫描）
    pub literals_hit: FxHashSet<&'a str>,
    pub any_hit: FxHashSet<&'a str>,
}

impl<'a> HeaderEvidence<'a> {
    /// 构建Header/Cookie证据快照（优化点：合并扫描）
    #[inline(always)]
    pub fn build(
        header_map: &'a FxHashMap<String, String>,
        cookies: &'a [StandardCookie],
        ac_literal: &AhoCorasick,
        ac_any: &AhoCorasick,
        header_tokens: FxHashSet<String>,
    ) -> Self {
        let mut literals_hit = FxHashSet::default();
        let mut any_hit = FxHashSet::default();
        // 优化1：Header的key + value 合并扫描（而非只扫value）
        for (key, val) in header_map {
            // 扫描Header key
            Self::scan_and_collect(key, ac_literal, &mut literals_hit);
            Self::scan_and_collect(key, ac_any, &mut any_hit);

            // 扫描Header value
            Self::scan_and_collect(val, ac_literal, &mut literals_hit);
            Self::scan_and_collect(val, ac_any, &mut any_hit);
        }

        // 优化2：Cookie扫描（合并到同一循环，减少迭代）
        for cookie in cookies {
            // 扫描 cookie 名
            Self::scan_and_collect(&cookie.name, ac_literal, &mut literals_hit);
            Self::scan_and_collect(&cookie.name, ac_any, &mut any_hit);
            // 扫描 cookie 值
            Self::scan_and_collect(&cookie.value, ac_literal, &mut literals_hit);
            Self::scan_and_collect(&cookie.value, ac_any, &mut any_hit);
        }

        Self {
            header_map,
            cookies,
            header_tokens,
            literals_hit,
            any_hit,
        }
    }

    /// 通用扫描函数
    #[inline(always)]
    fn scan_and_collect(s: &'a str, ac: &AhoCorasick, hits: &mut FxHashSet<&'a str>) {
        for mat in ac.find_iter(s) {
            hits.insert(&s[mat.start()..mat.end()]);
        }
    }
}
