//! HTML标签提取器
//! 负责从HTML中提取script-src和meta标签

use std::cell::RefCell;
use html5ever::tokenizer::{
    BufferQueue, Tag, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts
};
use markup5ever::interface::Attribute;
use tendril::StrTendril;

#[derive(Debug, Default, Clone)]
pub struct HtmlExtractor {
    script_srcs: RefCell<Vec<String>>,
    meta_tags: RefCell<Vec<(String, String)>>,
}

impl TokenSink for HtmlExtractor {
    type Handle = ();

    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        if let Token::TagToken(Tag {
            kind: TagKind::StartTag,
            name,
            attrs,
            ..
        }) = token
        {
            match name.as_ref() {
                "script" => self.extract_script_src(&attrs),
                "meta" => self.extract_meta_tags(&attrs),
                _ => {}
            }
        }
        TokenSinkResult::Continue
    }
}

impl HtmlExtractor {
    /// 创建新的提取器
    pub fn new() -> Self {
        Self::default()
    }

    /// 从HTML字符串提取标签
    pub fn extract(&self, html: &str) -> Self {
        let tokenizer = Tokenizer::new(self.clone(), TokenizerOpts::default());
        let queue = BufferQueue::default();
        queue.push_back(StrTendril::from(html));

        let _ = tokenizer.feed(&queue);
        tokenizer.end();

        tokenizer.sink
    }

    /// 提取script-src
    fn extract_script_src(&self, attrs: &[Attribute]) {
        for attr in attrs {
            if attr.name.local.as_ref() == "src" {
                self.script_srcs.borrow_mut().push(attr.value.to_string());
                break;
            }
        }
    }

    /// 提取meta标签
    fn extract_meta_tags(&self, attrs: &[Attribute]) {
        let mut name = None;
        let mut content = None;

        for attr in attrs {
            match attr.name.local.as_ref() {
                "name" => name = Some(attr.value.to_string().to_lowercase()),
                "content" => content = Some(attr.value.to_string()),
                _ => {}
            }
        }

        if let (Some(n), Some(c)) = (name, content) {
            self.meta_tags.borrow_mut().push((n, c));
        }
    }

    /// 获取提取到的script-src列表
    pub fn get_script_srcs(&self) -> Vec<String> {
        self.script_srcs.borrow().clone()
    }

    /// 获取提取到的meta标签列表
    pub fn get_meta_tags(&self) -> Vec<(String, String)> {
        self.meta_tags.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_extractor() {
        let html = r#"
            <script src="/jquery.min.js"></script>
            <meta name="author" content="test_user">
            <meta name="generator" content="WordPress 6.0" />
            <script src="/vue.global.js"></script>
        "#;

        let extractor = HtmlExtractor::new();
        let result = extractor.extract(html);

        assert_eq!(
            result.get_script_srcs(),
            vec!["/jquery.min.js".to_string(), "/vue.global.js".to_string()]
        );

        assert_eq!(
            result.get_meta_tags(),
            vec![
                ("author".to_string(), "test_user".to_string()),
                ("generator".to_string(), "WordPress 6.0".to_string())
            ]
        );
    }
}