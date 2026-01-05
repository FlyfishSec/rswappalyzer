//! 提取模块：从原始数据中提取检测所需信息
pub mod html_extractor;
//pub mod html_extractor_rc;
//pub mod html_extractor3_h5;

pub mod html_input_guard;
pub mod token_extract;

pub use self::html_extractor::HtmlExtractor;