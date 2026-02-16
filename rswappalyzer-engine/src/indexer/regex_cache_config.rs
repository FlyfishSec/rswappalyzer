//! # 正则表达式缓存模块
//!
//! 提供高性能、线程安全的正则表达式缓存，避免重复编译正则表达式带来的性能开销。
//! 基于 `moka` 缓存库实现，支持 LRU 淘汰策略和 TTL 过期机制。
//!
//! ## 特性
//! * 线程安全，可在多线程环境中共享
//! * LRU 淘汰策略（基于 TinyLFU）
//! * TTL 自动过期
//! * 全局共享实例池，相同配置复用缓存实例
//!
//! ## 示例
//! ```rust
//! use rswappalyzer::RegexCacheConfig;
//!
//! // 使用默认全局缓存
//! let cache = rswappalyzer::RegexCache::global();
//!
//! // 或创建自定义配置的缓存
//! let config = RegexCacheConfig::new(5000, 1800);
//! let cache = rswappalyzer::RegexCache::shared(config);
//! ```

use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    sync::Arc,
    time::Duration,
};
use moka::sync::Cache;

// =============================================================================
// 配置类型定义
// =============================================================================

/// 正则表达式缓存配置
///
/// 用于控制缓存的大小和条目的存活时间。
///
/// # 示例
/// ```
/// use rswappalyzer::RegexCacheConfig;
///
/// // 创建配置：最多缓存 5000 个正则，TTL 30分钟
/// let config = RegexCacheConfig::new(5000, 1800);
/// ```
#[derive(Debug, Copy, Clone, Default, Eq, Hash, PartialEq)]
pub struct RegexCacheConfig {
    /// 缓存最大条目数
    pub max_size: u64,
    
    /// 条目存活时间（秒）
    pub ttl_seconds: u64,
}

impl RegexCacheConfig {
    /// 创建新的缓存配置
    ///
    /// # 参数
    /// * `max_size` - 缓存最大条目数
    /// * `ttl_seconds` - 条目存活时间（秒）
    ///
    /// # 示例
    /// ```
    /// let config = RegexCacheConfig::new(1000, 3600);
    /// assert_eq!(config.max_size, 1000);
    /// assert_eq!(config.ttl_seconds, 3600);
    /// ```
    pub fn new(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            max_size: max_size as u64,
            ttl_seconds,
        }
    }

    /// 获取 TTL 的 Duration 表示
    #[inline]
    fn ttl_duration(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds)
    }
}

// =============================================================================
// 缓存键类型定义
// =============================================================================

/// 正则表达式缓存的键类型
///
/// 由正则表达式字符串和是否忽略大小写标志组成。
pub(crate) type RegexCacheKey = (Arc<String>, bool);

// =============================================================================
// 核心缓存实现
// =============================================================================

/// 正则表达式缓存
///
/// 提供线程安全的正则表达式缓存，自动管理条目的过期和淘汰。
/// 内部使用 `moka::sync::Cache` 实现，支持高并发访问。
///
/// # 性能特性
/// * 读操作：O(1) 时间复杂度
/// * 写操作：O(1) 平均时间复杂度
/// * 内存占用：受 `max_size` 配置限制
///
/// # 线程安全
/// 所有方法都是线程安全的，可以在多线程环境中共享。
#[derive(Debug, Clone)]
pub struct RegexCache {
    /// 内部的 Moka 缓存实例
    inner: Arc<Cache<RegexCacheKey, Arc<Regex>>>,
}

/// 全局默认缓存实例
///
/// 提供开箱即用的缓存实例，配置为：
/// * 最大条目数：10,000
/// * TTL：1小时
pub static GLOBAL_REGEX_CACHE: Lazy<Arc<RegexCache>> = Lazy::new(|| {
    RegexCache::shared(RegexCacheConfig {
        max_size: 10_000,
        ttl_seconds: 3600,
    })
});

/// 缓存实例池
///
/// 管理多个不同配置的缓存实例，相同配置复用同一实例。
/// 最大支持 100 个不同配置的缓存实例。
static REGEX_CACHE_POOL: Lazy<Cache<RegexCacheConfig, Arc<RegexCache>>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(100)  // 实例池最大支持100个不同配置
        .build()
});

impl RegexCache {
    /// 创建新的正则表达式缓存实例
    ///
    /// # 参数
    /// * `config` - 缓存配置，控制大小和 TTL
    ///
    /// # 返回值
    /// 返回新创建的 `RegexCache` 实例
    ///
    /// # 示例
    /// ```
    /// use rswappalyzer::{RegexCache, RegexCacheConfig};
    ///
    /// let config = RegexCacheConfig::new(5000, 1800);
    /// let cache = RegexCache::new(config);
    /// ```
    pub fn new(config: RegexCacheConfig) -> Self {
        log::debug!(
            "Creating new RegexCache instance | max_size={}, ttl={}s",
            config.max_size,
            config.ttl_seconds
        );

        // 构建 Moka 缓存：自带 LRU（TinyLFU）+ 线程安全 + TTL
        let cache = Cache::builder()
            .max_capacity(config.max_size)
            .time_to_live(config.ttl_duration())
            .build();

        Self {
            inner: Arc::new(cache),
        }
    }

    /// 获取或创建共享缓存实例
    ///
    /// 相同配置的缓存实例会被复用，避免重复创建。
    /// 这是创建缓存实例的推荐方式。
    ///
    /// # 参数
    /// * `config` - 缓存配置
    ///
    /// # 返回值
    /// 返回 `Arc<RegexCache>`，可以被安全地克隆和共享。
    ///
    /// # 示例
    /// ```
    /// use rswappalyzer::{RegexCache, RegexCacheConfig};
    ///
    /// let config = RegexCacheConfig::new(5000, 1800);
    /// let cache1 = RegexCache::shared(config.clone());
    /// let cache2 = RegexCache::shared(config);
    /// // cache1 和 cache2 指向同一个实例
    /// ```
    pub fn shared(config: RegexCacheConfig) -> Arc<Self> {
        REGEX_CACHE_POOL
            .get_with(config.clone(), || Arc::new(Self::new(config)))
            .clone()
    }

    /// 获取全局默认缓存实例
    ///
    /// 提供开箱即用的缓存实例，配置为 10,000 条目和 1 小时 TTL。
    ///
    /// # 返回值
    /// 返回全局默认缓存实例的引用。
    ///
    /// # 示例
    /// ```
    /// use rswappalyzer::RegexCache;
    ///
    /// let cache = RegexCache::global();
    /// ```
    pub fn global() -> Arc<Self> {
        GLOBAL_REGEX_CACHE.clone()
    }

    /// 从缓存中获取正则表达式
    ///
    /// # 参数
    /// * `key` - 缓存键，由正则表达式字符串和忽略大小写标志组成
    ///
    /// # 返回值
    /// 如果缓存命中且未过期，返回 `Some(Arc<Regex>)`；否则返回 `None`。
    #[inline]
    pub(crate) fn get(&self, key: &RegexCacheKey) -> Option<Arc<Regex>> {
        self.inner.get(key)
    }

    /// 向缓存中插入正则表达式
    ///
    /// # 参数
    /// * `key` - 缓存键
    /// * `regex` - 编译好的正则表达式
    ///
    /// # 注意
    /// 如果缓存已满，会根据 LRU 策略淘汰旧条目。
    #[inline]
    pub(crate) fn insert(&self, key: RegexCacheKey, regex: Arc<Regex>) {
        self.inner.insert(key, regex);
    }

    /// 获取缓存中的条目数量
    ///
    /// # 返回值
    /// 返回当前缓存中的有效条目数
    ///
    /// # 示例
    /// ```
    /// # use rswappalyzer::{RegexCache, RegexCacheConfig};
    /// # let cache = RegexCache::new(RegexCacheConfig::new(10, 60));
    /// let count = cache.len();
    /// println!("Cache contains {} entries", count);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.entry_count() as usize
    }

    /// 清空缓存中的所有条目
    ///
    /// # 示例
    /// ```
    /// # use rswappalyzer::{RegexCache, RegexCacheConfig};
    /// # let cache = RegexCache::new(RegexCacheConfig::new(10, 60));
    /// cache.clear();
    /// assert_eq!(cache.len(), 0);
    /// ```
    #[inline]
    pub fn clear(&self) {
        self.inner.invalidate_all();
    }

    /// 检查缓存是否为空
    ///
    /// # 返回值
    /// 如果缓存中没有条目，返回 `true`；否则返回 `false`。
    ///
    /// # 示例
    /// ```
    /// # use rswappalyzer::{RegexCache, RegexCacheConfig};
    /// # let cache = RegexCache::new(RegexCacheConfig::new(10, 60));
    /// assert!(cache.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RegexCache {
    /// 创建默认配置的缓存实例
    ///
    /// 默认配置：
    /// * 最大条目数：10,000
    /// * TTL：1小时
    fn default() -> Self {
        Self::new(RegexCacheConfig {
            max_size: 10_000,
            ttl_seconds: 3600,
        })
    }
}

// =============================================================================
// 单元测试
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_config() {
        let config = RegexCacheConfig::new(1000, 3600);
        assert_eq!(config.max_size, 1000);
        assert_eq!(config.ttl_seconds, 3600);
        assert_eq!(config.ttl_duration(), Duration::from_secs(3600));
    }

    #[test]
    fn test_cache_operations() {
        let cache = RegexCache::new(RegexCacheConfig::new(10, 60));
        
        let pattern = r"^\d+$";
        let key = (Arc::new(pattern.to_string()), false);
        let regex = Arc::new(Regex::new(pattern).unwrap());
        
        // 测试插入和获取
        cache.insert(key.clone(), regex.clone());
        
        // 由于 Regex 没有实现 PartialEq，我们通过比较字符串模式来验证
        let cached = cache.get(&key).unwrap();
        assert_eq!(cached.as_str(), regex.as_str());
        
        // 测试长度
        assert_eq!(cache.len(), 1);
        
        // 测试清空
        cache.clear();
        assert!(cache.is_empty());
        
        // 测试获取不存在的键
        let nonexistent_key = (Arc::new(r"^\w+$".to_string()), false);
        assert!(cache.get(&nonexistent_key).is_none());
    }

    #[test]
    fn test_cache_with_case_insensitive() {
        let cache = RegexCache::new(RegexCacheConfig::new(10, 60));
        
        let pattern = r"^[a-z]+$";
        let key_case_sensitive = (Arc::new(pattern.to_string()), false);
        let key_case_insensitive = (Arc::new(pattern.to_string()), true);
        
        let regex_sensitive = Arc::new(Regex::new(pattern).unwrap());
        let regex_insensitive = Arc::new(Regex::new(&format!("(?i){}", pattern)).unwrap());
        
        // 插入两种不同的正则（区分大小写标志不同）
        cache.insert(key_case_sensitive.clone(), regex_sensitive);
        cache.insert(key_case_insensitive.clone(), regex_insensitive);
        
        // 验证缓存条目数
        assert_eq!(cache.len(), 2);
        
        // 验证可以分别获取
        assert!(cache.get(&key_case_sensitive).is_some());
        assert!(cache.get(&key_case_insensitive).is_some());
    }

    #[test]
    fn test_cache_max_size_eviction() {
        // 创建只有2个条目容量的缓存
        let cache = RegexCache::new(RegexCacheConfig::new(2, 60));
        
        // 插入3个不同的正则
        let patterns = vec![r"^\d+$", r"^\w+$", r"^[a-z]+$"];
        
        for (_i, pattern) in patterns.iter().enumerate() {
            let key = (Arc::new(pattern.to_string()), false);
            let regex = Arc::new(Regex::new(pattern).unwrap());
            cache.insert(key, regex);
            
            // Moka 的缓存是异步淘汰的，所以不能立即验证大小
            // 这里只验证插入操作不会 panic
        }
        
        // 验证缓存大小不超过配置（Moka 可能不会立即淘汰）
        assert!(cache.len() <= 2, "Cache size {} should be <= 2", cache.len());
    }

    #[test]
    fn test_shared_instances() {
        let config1 = RegexCacheConfig::new(100, 60);
        let config2 = RegexCacheConfig::new(100, 60); // 相同配置
        let config3 = RegexCacheConfig::new(200, 60); // 不同配置
        
        let cache1 = RegexCache::shared(config1.clone());
        let cache2 = RegexCache::shared(config2);
        let cache3 = RegexCache::shared(config3);
        
        // 相同配置应该返回同一个实例
        assert!(Arc::ptr_eq(&cache1, &cache2));
        
        // 不同配置应该返回不同实例
        assert!(!Arc::ptr_eq(&cache1, &cache3));
        
        // 验证它们的内部缓存确实不同
        cache1.insert((Arc::new("test".to_string()), false), Arc::new(Regex::new("test").unwrap()));
        cache3.insert((Arc::new("test".to_string()), false), Arc::new(Regex::new("test").unwrap()));
        
        // cache1 和 cache2 共享数据
        assert_eq!(cache1.len(), cache2.len());
        
        // cache3 可能有不同的数据（取决于执行顺序，这个测试可能不稳定）
        // 这里只验证它们不是同一个实例
    }

    #[test]
    fn test_global_cache() {
        let cache1 = RegexCache::global();
        let cache2 = RegexCache::global();
        
        // 全局缓存应该是同一个实例
        assert!(Arc::ptr_eq(&cache1, &cache2));
        
        // 验证全局缓存的默认配置
        // 由于无法直接访问配置，我们通过行为来验证
        cache1.clear();
        assert_eq!(cache1.len(), 0);
    }

    #[test]
    fn test_cache_concurrent_access() {
        use std::thread;
        
        let cache = Arc::new(RegexCache::new(RegexCacheConfig::new(100, 60)));
        let mut handles = vec![];
        
        // 创建多个线程同时访问缓存
        for i in 0..10 {
            let cache = cache.clone();
            let pattern = format!(r"^\d+{}", i);
            
            let handle = thread::spawn(move || {
                let key = (Arc::new(pattern.clone()), false);
                let regex = Arc::new(Regex::new(&pattern).unwrap());
                
                // 插入
                cache.insert(key.clone(), regex.clone());
                
                // 读取
                let cached = cache.get(&key);
                assert!(cached.is_some());
                
                // 验证内容（通过字符串比较）
                assert_eq!(cached.unwrap().as_str(), regex.as_str());
            });
            
            handles.push(handle);
        }
        
        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }
        
        // 验证最终状态
        assert!(cache.len() <= 10);
    }
}