//! Header格式转换工具
use log::warn;
use http::header::HeaderMap;
use rustc_hash::FxHashMap;

/// Header转换工具
pub struct HeaderConverter;

impl HeaderConverter {
    /// 将HeaderMap转换为FxHashMap<String, Vec<String>>
    pub fn to_hashmap(header_map: &HeaderMap) -> FxHashMap<String, Vec<String>> {
        let mut map = FxHashMap::default();
        let mut iter_count = 0;

        for (key, value) in header_map.iter() {
            iter_count += 1;
            if iter_count > 1000 {
                warn!("Header迭代超过1000次，强制终止");
                break;
            }

            let key_str = key.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("").to_lowercase();

            map.entry(key_str).or_insert_with(Vec::new).push(value_str);
        }
        map
    }

    /// 将FxHashMap<String, Vec<String>>转换为单值FxHashMap<String, String>
    pub fn to_single_value(hashmap: &FxHashMap<String, Vec<String>>) -> FxHashMap<String, String> {
        let mut single_map = FxHashMap::default();
        for (key, values) in hashmap {
            if let Some(first_val) = values.iter().find(|v| !v.is_empty()) {
                single_map.insert(key.clone(), first_val.clone());
            }
        }
        single_map
    }

    /// 双返回值，单值headerMap + 原始cookie的headerMap（未解析）
    pub fn convert_all(
        headers: &HeaderMap,
    ) -> (FxHashMap<String, String>, FxHashMap<String, Vec<String>>) {
        let mut single_header_map = FxHashMap::default();
        let mut cookie_map: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let mut iter_count = 0;

        for (k, v) in headers.iter() {
            iter_count += 1;
            if iter_count > 1000 {
                warn!("Header迭代超过1000次，强制终止");
                break;
            }

            let key = k.as_str().to_ascii_lowercase();
            let value = v.to_str().unwrap_or("").to_string();

            if key == "cookie" || key == "set-cookie" {
                cookie_map.entry(key).or_default().push(value);
            } else {
                single_header_map.entry(key).or_insert(value);
            }
        }

        (single_header_map, cookie_map)
    }

    // 解析原始cookie_header_map → 标准化Cookie KV结构
    // 入参：原始的 { "set-cookie": [...], "cookie": [...] }
    // 出参：FxHashMap<String, Vec<String>> 标准化结构
    pub fn parse_to_standard_cookie(
        raw_cookie_header_map: &FxHashMap<String, Vec<String>>
    ) -> FxHashMap<String, Vec<String>> {
        let mut standard_cookies = FxHashMap::default();

        for (header_name, raw_cookie_values) in raw_cookie_header_map {
            match header_name.as_str() {
                "set-cookie" => {
                    for raw in raw_cookie_values {
                        Self::parse_set_cookie_fast(raw, &mut standard_cookies);
                    }
                }
                "cookie" => {
                    for raw in raw_cookie_values {
                        Self::parse_request_cookie_fast(raw, &mut standard_cookies);
                    }
                }
                _ => continue,
            }
        }

        standard_cookies
    }

    // 快速解析Set-Cookie，极简过滤deleted Cookie
    fn parse_set_cookie_fast(raw_cookie: &str, standard_cookies: &mut FxHashMap<String, Vec<String>>) {
        let cookie_str = raw_cookie.trim();
        if cookie_str.is_empty() { return; }

        let mut segments = cookie_str.split(';').map(|s| s.trim()).filter(|s| !s.is_empty());
        let Some(core_kv) = segments.next() else { return; };

        let eq_pos = core_kv.find('=');
        let (name, value) = match eq_pos {
            None => return,
            Some(pos) => (core_kv[0..pos].trim(), core_kv[pos+1..].trim()),
        };

        // 1. Cookie名不能为空 2. 值不能是deleted → 完全满足指纹识别需求
        if name.is_empty() || value.eq_ignore_ascii_case("deleted") {
            return;
        }

        let name_lc = name.to_ascii_lowercase();

        standard_cookies.entry(name_lc)
            .or_insert_with(Vec::new)
            .push(value.to_string());
    }

    // 快速解析Request-Cookie
    fn parse_request_cookie_fast(raw_cookie: &str, standard_cookies: &mut FxHashMap<String, Vec<String>>) {
        let cookie_str = raw_cookie.trim();
        if cookie_str.is_empty() { return; }

        for core_kv in cookie_str.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let eq_pos = core_kv.find('=');
            let (name, value) = match eq_pos {
                None => continue,
                Some(pos) => (core_kv[0..pos].trim(), core_kv[pos+1..].trim()),
            };

            if name.is_empty() || value.eq_ignore_ascii_case("deleted") {
                continue;
            }

            let name_lc = name.to_ascii_lowercase();

            standard_cookies.entry(name_lc)
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }
    }
}