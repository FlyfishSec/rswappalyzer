//! 检测结果更新工具
use rustc_hash::{FxHashMap, FxHashSet};

use crate::rule::indexer::index_pattern::CompiledRuleLibrary;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::hash::BuildHasher; // ✅ 核心：泛型哈希器，兼容所有HashMap/FxHashMap

/// 检测结果更新工具
pub struct DetectionUpdater;

impl DetectionUpdater {
    /// 更新检测结果（智能判断是否更新，取最优结果）
    /// 泛型化哈希器 S: BuildHasher，兼容 标准HashMap + FxHashMap
    pub fn update<S: BuildHasher>(
        detected: &mut HashMap<String, (u8, Option<String>), S>,
        tech_name: &str,
        confidence: Option<u8>,
        version: Option<String>,
    ) {
        // 1. 处理默认值：置信度默认100，版本默认None
        let new_conf = confidence.unwrap_or(100);
        let new_version = version;

        match detected.entry(tech_name.to_string()) {
            Entry::Occupied(mut entry) => {
                let (old_conf, old_version) = entry.get_mut();
                let need_update =
                    Self::is_new_result_better(new_conf, &new_version, *old_conf, old_version);

                if need_update {
                    *old_conf = new_conf;
                    *old_version = new_version;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert((new_conf, new_version));
            }
        }
    }

    // apply_implies 多来源支持 + 置信度加权
    // 返回值：FxHashMap<String, Vec<String>> → 推导技术名: [来源1, 来源2...]
    pub fn apply_implies<S: BuildHasher>(
        compiled_lib: &CompiledRuleLibrary,
        detected: &mut HashMap<String, (u8, Option<String>), S>,
    ) -> FxHashMap<String, Vec<String>> {
        // 推导技术名 → 所有来源技术名（自动去重，支持多来源）
        let mut imply_source_map: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
        // 推导技术的基础置信度 & 加权配置
        const BASE_IMPLY_CONF: u8 = 90;
        const MAX_IMPLY_CONF: u8 = 95;
        const BOOST_PER_SOURCE: u8 = 3;

        // 1. 遍历所有真实匹配的技术，收集多来源推导关系
        for source_tech_name in detected.keys() {
            if let Some(compiled_tech) = compiled_lib.tech_patterns.get(source_tech_name) {
                for target_tech_name in &compiled_tech.implies {
                    let target_tech_name = target_tech_name.trim();
                    // 过滤无效值：空字符串/目标技术不存在/目标已被真实匹配
                    if target_tech_name.is_empty() 
                        || !compiled_lib.tech_patterns.contains_key(target_tech_name)
                        || detected.contains_key(target_tech_name)
                    {
                        continue;
                    }
                    // 多来源收集
                    imply_source_map
                        .entry(target_tech_name.to_string())
                        .or_insert_with(FxHashSet::default)
                        .insert(source_tech_name.to_string());
                }
            }
        }

        // 2. 把推导技术写入detected，并根据来源数量做置信度加权
        for (target_tech, source_set) in &imply_source_map {
            let source_count = source_set.len() as u8;
            // 置信度加权：来源越多，置信度越高，最高不超过MAX_IMPLY_CONF
            let boost = std::cmp::min(source_count * BOOST_PER_SOURCE, MAX_IMPLY_CONF - BASE_IMPLY_CONF);
            let final_conf = BASE_IMPLY_CONF + boost;
            // 写入detected，版本为None
            detected.entry(target_tech.clone()).or_insert((final_conf, None));
        }

        // 3. HashSet转Vec，返回标准的【推导技术→来源列表】映射表
        let mut imply_map = FxHashMap::default();
        for (k, v) in imply_source_map {
            let mut source_vec = v.into_iter().collect::<Vec<_>>();
            source_vec.sort_unstable();
            imply_map.insert(k, source_vec);
        }

        imply_map
    }
    
    /// 辅助函数：判断新结果是否比旧结果更优
    fn is_new_result_better(
        new_conf: u8,
        new_version: &Option<String>,
        old_conf: u8,
        old_version: &Option<String>,
    ) -> bool {
        if new_conf > old_conf {
            return true;
        }
        if new_conf == old_conf {
            if old_version.is_none() && new_version.is_some() {
                return true;
            }
            if let (Some(new_ver), Some(old_ver)) = (new_version, old_version) {
                return new_ver.len() > old_ver.len();
            }
        }
        false
    }
}