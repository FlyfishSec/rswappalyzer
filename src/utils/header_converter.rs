//! Header格式转换工具
//! 不同Header格式之间的转换

use std::collections::HashMap;
use reqwest::header::HeaderMap;
use tracing::{debug, warn};
use std::time::Instant;

/// Header转换工具
pub struct HeaderConverter;

impl HeaderConverter {
    /// 将HeaderMap转换为HashMap<String, Vec<String>>
    pub fn to_hashmap(header_map: &HeaderMap) -> HashMap<String, Vec<String>> {
        let start = Instant::now();
        let mut map = HashMap::new();
        let mut iter_count = 0;

        for (key, value) in header_map.iter() {
            iter_count += 1;
            if iter_count > 1000 {
                warn!("Header迭代超过1000次，强制终止");
                break;
            }

            let key_str = key.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("").to_string();

            map.entry(key_str)
                .or_insert_with(Vec::new)
                .push(value_str);
        }

        debug!(
            "Header转换完成，耗时{:?}，生成{}条记录",
            start.elapsed(),
            map.len()
        );

        map
    }

    /// 将HashMap<String, Vec<String>>转换为单值HashMap<String, String>
    pub fn to_single_value(hashmap: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
        let mut single_map = HashMap::new();
        for (key, values) in hashmap {
            if let Some(first_val) = values.iter().find(|v| !v.is_empty()) {
                single_map.insert(key.clone(), first_val.clone());
            }
        }
        single_map
    }
}