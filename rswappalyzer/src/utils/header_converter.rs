use log::warn;
use http::header::HeaderMap;
use rswappalyzer_engine::input_evidence::header_evidence::StandardCookie;
use rustc_hash::FxHashMap;

/// Header转换工具结构体
/// 设计：无状态工具类，所有方法为关联函数（static）
pub struct HeaderConverter;

impl HeaderConverter {
    /// 将标准HeaderMap转换为FxHashMap<String, Vec<String>>
    /// 特性：
    /// 1. 迭代次数限制（最多1000次），防止恶意超大Header
    /// 2. 所有Key/Value转为小写，统一匹配规则
    /// 3. FxHashMap高性能哈希表，适合高频访问
    /// 参数：header_map - 标准HTTP HeaderMap
    /// 返回：转换后的多值Header哈希表
    pub fn to_hashmap(header_map: &HeaderMap) -> FxHashMap<String, Vec<String>> {
        let mut map = FxHashMap::default();
        let mut iter_count = 0;

        for (key, value) in header_map.iter() {
            iter_count += 1;
            // 安全防护：限制迭代次数，防止恶意构造的超大Header
            if iter_count > 1000 {
                warn!("Header iteration exceeded 1000 times, forced termination");
                break;
            }

            // 统一转为小写，避免大小写敏感问题
            let key_str = key.as_str().to_ascii_lowercase();
            let value_str = value.to_str().unwrap_or("").to_ascii_lowercase();

            // 按Key聚合多值Header
            map.entry(key_str).or_insert_with(Vec::new).push(value_str);
        }
        
        map
    }

    /// 将多值Header哈希表转换为单值Header哈希表
    /// 规则：取每个Key的第一个非空值
    /// 参数：hashmap - 多值Header哈希表
    /// 返回：单值Header哈希表（每个Key仅保留第一个非空值）
    pub fn to_single_value(hashmap: &FxHashMap<String, Vec<String>>) -> FxHashMap<String, String> {
        let mut single_map = FxHashMap::default();
        
        for (key, values) in hashmap {
            // 查找第一个非空值，忽略空值
            if let Some(first_val) = values.iter().find(|v| !v.is_empty()) {
                single_map.insert(key.clone(), first_val.clone());
            }
        }
        
        single_map
    }

    /// 批量转换Header（单值Header + Cookie专用Header）
    /// 特性：
    /// 1. 预分配哈希表容量，避免运行期扩容开销
    /// 2. 分离普通Header（单值）和Cookie Header（多值）
    /// 3. 迭代次数限制，防止恶意超大Header
    /// 参数：headers - 标准HTTP HeaderMap
    /// 返回：(单值普通Header哈希表, Cookie专用Header哈希表)
    pub fn convert_all(
        headers: &HeaderMap,
    ) -> (FxHashMap<String, String>, FxHashMap<String, Vec<String>>) {
        let mut single_header_map = FxHashMap::default();
        let mut cookie_map: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let mut iter_count = 0;

        // 预分配容量：避免运行期扩容，提升性能
        single_header_map.reserve(headers.len());
        cookie_map.reserve(2); // Cookie相关Header最多2个（cookie/set-cookie）

        for (k, v) in headers.iter() {
            iter_count += 1;
            // 安全防护：限制迭代次数
            if iter_count > 1000 {
                warn!("Header iteration exceeded 1000 times, forced termination");
                break;
            }

            // 统一转为小写ASCII，避免大小写问题
            let key = k.as_str().to_ascii_lowercase();
            // 安全转换Header值为字符串，失败则返回空字符串
            let value = match v.to_str() {
                Ok(s) => s.to_ascii_lowercase(),
                Err(_) => String::new(),
            };

            // 分离Cookie相关Header和普通Header
            if key == "cookie" || key == "set-cookie" {
                cookie_map.entry(key).or_default().push(value);
            } else {
                single_header_map.insert(key, value);
            }
        }

        (single_header_map, cookie_map)
    }

    /// 解析原始Cookie Header为标准化Cookie实体列表
    /// 输入：原始Cookie Header哈希表 { "set-cookie": [...], "cookie": [...] }
    /// 输出：标准化Cookie实体列表
    /// 特性：
    /// 1. 过滤deleted Cookie，避免无效匹配
    /// 2. 统一Cookie名小写，避免大小写敏感
    /// 3. 高性能解析，手写循环替代迭代器
    pub fn parse_to_standard_cookie(
        raw_cookie_header_map: &FxHashMap<String, Vec<String>>
    ) -> Vec<StandardCookie> {
        let mut standard_cookies = Vec::new();

        // 分别解析Set-Cookie和Request-Cookie
        for (header_name, raw_cookie_values) in raw_cookie_header_map {
            let source = header_name.as_str(); // 来源Header名称（"cookie"/"set-cookie"）
            match source {
                "set-cookie" => {
                    for raw in raw_cookie_values {
                        // 解析Set-Cookie并添加到列表
                        if let Some(cookie) = Self::parse_set_cookie_fast(raw, source) {
                            standard_cookies.push(cookie);
                        }
                    }
                }
                "cookie" => {
                    for raw in raw_cookie_values {
                        // 解析Request-Cookie（返回多个Cookie）
                        let cookies = Self::parse_request_cookie_fast(raw, source);
                        standard_cookies.extend(cookies);
                    }
                }
                _ => continue,
            }
        }

        standard_cookies
    }

    /// 快速解析Set-Cookie头为标准化Cookie实体
    /// 返回：Option<StandardCookie>（过滤无效Cookie）
    fn parse_set_cookie_fast(raw_cookie: &str, source: &str) -> Option<StandardCookie> {
        let cookie_str = raw_cookie.trim();
        if cookie_str.is_empty() { return None; }

        // 分割Cookie核心KV和属性（仅处理第一个分号前的内容）
        let mut segments = cookie_str.split(';').map(|s| s.trim()).filter(|s| !s.is_empty());
        let Some(core_kv) = segments.next() else { return None; };

        // 查找等号位置，分割Key和Value
        let eq_pos = core_kv.find('=')?;
        let (name, value) = (core_kv[0..eq_pos].trim(), core_kv[eq_pos+1..].trim());

        // 过滤规则：
        // 1. Cookie名不能为空
        // 2. Value不能是"deleted"（忽略已删除的Cookie）
        if name.is_empty() || value.eq_ignore_ascii_case("deleted") {
            return None;
        }

        // 统一Cookie名小写，构建实体
        Some(StandardCookie {
            name: name.to_ascii_lowercase(),
            value: value.to_string(),
            source: source.to_string(),
        })
    }

    /// 快速解析Request-Cookie头为标准化Cookie实体列表
    /// 返回：Vec<StandardCookie>（多个Cookie实体）
    fn parse_request_cookie_fast(raw_cookie: &str, source: &str) -> Vec<StandardCookie> {
        let mut cookies = Vec::new();
        let cookie_str = raw_cookie.trim();
        if cookie_str.is_empty() { return cookies; }

        // 手写split+trim+filter，替代链式迭代器，提升性能
        let mut start = 0;
        let bytes = cookie_str.as_bytes();
        
        for (i, &b) in bytes.iter().enumerate() {
            if b == b';' {
                let slice = &bytes[start..i];
                let core_kv = Self::trim_slice(slice);
                
                if !core_kv.is_empty() {
                    if let Some(cookie) = Self::parse_cookie_kv(core_kv, source) {
                        cookies.push(cookie);
                    }
                }
                
                start = i + 1;
            }
        }
        
        // 处理最后一个KV对
        let slice = &bytes[start..];
        let core_kv = Self::trim_slice(slice);
        
        if !core_kv.is_empty() {
            if let Some(cookie) = Self::parse_cookie_kv(core_kv, source) {
                cookies.push(cookie);
            }
        }

        cookies
    }

    /// 辅助函数：字节切片trim（零拷贝，比str.trim()更快）
    /// 特性：
    /// 1. 零拷贝：仅操作字节切片，无内存分配
    /// 2. ASCII空白符处理，适合HTTP Header场景
    /// 3. 内联优化，编译期嵌入调用处
    /// 参数：slice - 原始字节切片
    /// 返回：trim后的字节切片
    #[inline(always)]
    fn trim_slice(slice: &[u8]) -> &[u8] {
        // 查找第一个非空白字符的位置
        let start = slice.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(0);
        // 查找最后一个非空白字符的位置
        let end = slice.iter().rposition(|&b| !b.is_ascii_whitespace()).map_or(0, |i| i + 1);
        
        &slice[start..end]
    }

    /// 辅助函数：解析Cookie KV对为实体
    #[inline(always)]
    fn parse_cookie_kv(core_kv: &[u8], source: &str) -> Option<StandardCookie> {
        // 查找等号位置
        let eq_pos = core_kv.iter().position(|&b| b == b'=')?;
        let (name_slice, value_slice) = core_kv.split_at(eq_pos);
        
        // Trim名称和值
        let name = Self::trim_slice(name_slice);
        let value = if value_slice.is_empty() { 
            &[] 
        } else { 
            Self::trim_slice(&value_slice[1..]) 
        };

        // 过滤空名称
        if name.is_empty() { return None; }
        
        // UTF8安全转换，统一转为小写
        let name_str = String::from_utf8_lossy(name).to_ascii_lowercase();
        let value_str = String::from_utf8_lossy(value).to_string();
        
        // 过滤deleted值
        if value_str.eq_ignore_ascii_case("deleted") { return None; }
        
        // 构建标准化Cookie实体
        Some(StandardCookie {
            name: name_str,
            value: value_str,
            source: source.to_string(),
        })
    }
}