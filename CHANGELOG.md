# Changelog

## [Unreleased]

## [0.2.1] - 2026-01-09

### Changed

- 优化代码逻辑检测速度再次提升47.16%

### Fixed

- 修复一个导致小部分Header规则失效的隐藏bug

## [0.2.0] - 2026-01-08

### Added

- 全新引擎架构升级，核心模块重构，引入剪枝引擎，毫秒级启动和检测  
- 支持自定义规则源从自定义目录或字对应远程URL（需开启`remote-loader`特性）
- 默认内嵌官方 Wappalyzer 规则库（默认`embededd-rules`特性）
- 标准化输出结构：`name`, `version`, `categories`, `confidence`, `implied_by`  

### Changed

- 放弃启动时全量正则编译策略  
- 大量资源利用效率优化
- 规则源不再主动请求拉取

### Fixed

- 修复1.0版本多个bug

### Removed

---

## [0.1.0] - 2025-12-20

### Added

- 初始版本发布  
