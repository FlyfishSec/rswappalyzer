use crate::Scope;

/// Pattern类型标记
/// 用于区分不同的匹配规则类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternKind {
    /// 剪枝层：精确字面量匹配
    Literal,
    /// 剪枝层：任意匹配
    Any,
    /// 匹配层：包含匹配（需转换为小写）
    Contains,
}

/// Pattern元信息
/// 关联Pattern的类型和作用域信息
#[derive(Debug, Clone)]
pub struct PatternMeta {
    /// Pattern类型标记
    pub kind: PatternKind,
    /// Pattern所属作用域（便于后续扩展）
    pub scope: Scope,
}
