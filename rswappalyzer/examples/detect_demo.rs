// examples/detect_demo.rs
// rswappalyzer 库自测示例 - 测试完整指纹识别能力
// 运行命令：cargo run --example detect_demo
use env_logger::{Builder, Env};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer::{RuleConfig, RuleOrigin, TechDetector};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Builder::from_env(Env::default().default_filter_or("debug"))
        .target(env_logger::Target::Stdout)
        .init();

    // 1. 初始化检测器
    let config = RuleConfig {
        origin: RuleOrigin::Embedded,
        ..RuleConfig::default()
    };
    let detector = TechDetector::with_embedded_rules(config)?;
    println!("指纹检测器初始化完成，使用内置固化规则库");

    // 2. 构造你的测试数据
    // 2.1 构造请求头 HeaderMap
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
    // headers.append(
    //     HeaderName::from_static("set-cookie"),
    //     HeaderValue::from_static("simplocms_session=xyz987; Path=/; HttpOnly"),
    // );
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

    // 2.2 目标URL数组
    let urls = &["https://example.com/"];

    // 2.3 完整HTML响应体
    let html_body = r#"<!DOCTYPE html>
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
</script>"#;

    // 3. 执行指纹检测 + 耗时统计
    use std::time::Instant;
    let start_time = Instant::now();
    let detect_result = detector.detect_with_time(&headers, urls, html_body.as_bytes())?;
    let cost_time = start_time.elapsed();

    // 打印检测完成信息 + 精准耗时 (毫秒+三位小数)
    println!("指纹检测完成，结果如下：");
    println!("--------------------------------------------------------------------------------");
    println!("检测耗时: {:.3} ms", cost_time.as_secs_f64() * 1000.0);
    println!("--------------------------------------------------------------------------------");

    // 原始格式化JSON结构输出
    let json_str = serde_json::to_string_pretty(&detect_result)?;
    println!("{}", json_str);

    Ok(())
}
