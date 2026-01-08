// examples/test_data.rs
use http::header::{HeaderMap, HeaderName, HeaderValue};

/// 获取测试用的请求头
#[allow(dead_code)]
pub fn get_test_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("private"),
    );
    headers.insert(
        HeaderName::from_static("transfer-encoding"),
        HeaderValue::from_static("chunked"),
    );
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("ASP.NET_SessionId=1hmbvexm23c1gqaaptjqedhr; Path=/; HttpOnly"),
    );
    headers.insert(
        HeaderName::from_static("p3p"),
        HeaderValue::from_static("CP=CAO PSA OUR"),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("ASP.NET"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("OPTIONS,POST,GET"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("x-requested-with"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    headers.insert(
        HeaderName::from_static("date"),
        HeaderValue::from_static("Thu, 01 Jan 2026 02:37:48 GMT"),
    );
    headers
}

/// 获取测试用的目标URL数组
#[allow(dead_code)]
pub fn get_test_urls() -> &'static [&'static str] {
    &["https://example.com/"]
}

/// 获取测试用的HTML响应体
#[allow(dead_code)]
pub fn get_test_html_body() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="generator" content="wisy cms 5.8.2" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black">
    <meta name="format-detection" content="telephone=no">
    <meta http-equiv="Expires" content="-1">
    <meta http-equiv="Cache-Control" content="no-cache">
    <meta http-equiv="Pragma" content="no-cache">
    <title>test</title>
    <link rel="stylesheet" href="slimbox.css">
    <!--图片弹出层样式 必要样式-->
    <link rel="stylesheet" href="../htmls/Web/css/iconfont.min.css" />
    <script src="../htmls/Web/js/jquery-1.9.1.min.js"></script>
    <script src="../htmls/Web/js/gVerify.js"></script>
    <script>
        var now = new Date().getTime();

        document.write('<link rel="stylesheet" type="text/css" href="../htmls/Web/css/base.css?v=' + now + '"/>');
        document.write('<link rel="stylesheet" type="text/css" href="../htmls/Web/css/liuyan.css?v=' + now + '"/>');
       </script>
</head>
<body>

    <div class="banner">
        <img src="../htmls/Web/images/logo.JPG" width="100%" />
    </div>
<div class="photopile-wrapper">

        <form class="ly_box">
         <input type="hidden" value="0" id="tag" />
         <input type="hidden" value="openid" name="openid" />
                                <ul class="left-form-box">

                                        <li>
                                                <a href="toushu.aspx?deptid=0">test</a>
                                                <a href="city.aspx?deptid=2">test</a>
                                        </li>
                                        <li><a href="ShowNotice.aspx?deptid=51" style="width:243px">test</br>test</a></li>
                                </ul>

                                <div class="clear"> </div>

                        </form>
</div>
<script type="text/javascript">
    window.onload = function ()
        {
                window.location.href = "ShowNotice.aspx?deptid=51";
        } 　　
</script>"#
}

#[allow(dead_code)]
fn main() {}