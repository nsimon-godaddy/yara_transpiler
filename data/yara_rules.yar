rule backdoor_curl_002
{
    meta:
        description = "Converted from JSON signature backdoor.curl.002"

    strings:
    $fullchain0 = "AfterFilterCallbac" ascii
    $fullchain1 = "curl${IFS%??}-" ascii
    $cleanup_pattern = /\{\{\s*var this\.getTem[\w%]+ter\(\)\.add[\w%]+Callback\((system|shell_exec)\)\.[Ff]ilter\([^\)]*\bcurl\$\{IFS%\?\?\}-[^\)]+\.php[^\)]+\)\}\}/

    condition:
        all of ($fullchain*)
}

rule backdoor_eval_001
{
    meta:
        description = "Converted from JSON signature backdoor.eval.001"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "onmouseover=\"eval(atob(" ascii
    $cleanup_pattern = /\[<a title="\]" rel="nofollow"><\/a>\[\S+ <!-- style=\W*\S+\s+onmouseover=.eval\(atob\(\W+dmFyIHggPSBkb2N1bWVudC5nZXRFbGVtZW50c0J5VGFnTmFtZSgiYSI[^\);\s]+\)\)['"]\s*&gt;[^<]+<a><\/a>\]/

    condition:
        all of ($fullchain*)
}

rule backdoor_eval_009
{
    meta:
        description = "Converted from JSON signature backdoor.eval.009"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "base64_decode" ascii
    $fullchain2 = "eval(base64_decode" ascii
    $fullchain3 = "ZWQoJEJPT1RfTkFNRSkpe31kZWZpbmUoJEJPT1RfTkFNRSwnMScpO3NldF90aW" ascii
    $cleanup_pattern = /eval\(base64_decode\(.JEJP[^;]+\);/

    condition:
        all of ($fullchain*)
}

rule backdoor_eval_base64_022
{
    meta:
        description = "Converted from JSON signature backdoor.eval_base64.022"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "eval(atob(" ascii
    $cleanup_pattern = /eval\(atob\(.ZnVu[^\)]+[\);]+/

    condition:
        all of ($fullchain*)
}

rule backdoor_eval_base64_024
{
    meta:
        description = "Converted from JSON signature backdoor.eval_base64.024"

    strings:
    $fullchain0 = "ZX" ascii
    $fullchain1 = "CgppZighZGVmaW5lZCgnRE9MTFlfV0FZ" ascii
    $cleanup_pattern = /CgppZighZGVmaW5lZCgnRE9MTFlfV0FZ[^\s]*/

    condition:
        all of ($fullchain*)
}

rule backdoor_evalphp_004
{
    meta:
        description = "Converted from JSON signature backdoor.evalphp.004"

    strings:
    $fullchain0 = "base64" ascii
    $fullchain1 = "[evalphp]" ascii
    $fullchain2 = "[evalphp]system (" ascii
    $cleanup_pattern = /\[evalphp\]\s*system\s*\(.echo [^\),\|"']+\|\s*base64\s+-d\s*\|\s*tee \w+\.php["']\);\s*\[\/evalphp\]/

    condition:
        all of ($fullchain*)
}

rule backdoor_magento_template_001
{
    meta:
        description = "Converted from JSON signature backdoor.magento_template.001"

    strings:
    $fullchain0 = "AfterFilterCallbac" ascii
    $fullchain1 = "k(base64_decode)" ascii
    $fullchain2 = "k(system).Filter(Y2Qgc" ascii
    $cleanup_pattern = /(error\{\{|sys\{\{|\{\{var[\s]*)?(if[\s]*)?this\.getTemp[^\}\/]+FilterCall[^\(,\.\{]+\(base64_decode.\.add(%00)?\w*AfterFilterCall[^\(,\.\{]+k\(system..Filter.Y2[\w\/\+=-]+(\)\}\}[\w]+\{\{.if\}\}|\)\}\})?/

    condition:
        all of ($fullchain*)
}

rule backdoor_magento_template_002
{
    meta:
        description = "Converted from JSON signature backdoor.magento_template.002"

    strings:
    $fullchain0 = "AfterFilterCallbac" ascii
    $fullchain1 = "k(base64_decode)" ascii
    $fullchain2 = "~if this.getT[^\\}\\/]+FilterCallback.base64_decode.\\.add(%00)?\\w*AfterFilterCallback.(system|unserialize)..Filter~" ascii
    $cleanup_pattern = /if this.getT[^\}\/]+FilterCallback.base64_decode.\.add(%00)?\w*AfterFilterCallback.(system|unserialize)..Filter\(\w[^\)\}]+\)/

    condition:
        all of ($fullchain*)
}

rule backdoor_obfuscated_003
{
    meta:
        description = "Converted from JSON signature backdoor.obfuscated.003"

    strings:
    $fullchain0 = "tmp" ascii
    $fullchain1 = "3c3f706870202470706f7374653d247468656d65735f637373" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_080
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.080"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "atob" ascii
    $fullchain2 = "(function(i,s,o,g,r,a,m)" ascii
    $fullchain3 = ".getElementsByTagName(g)[0];if(i.location" ascii
    $cleanup_pattern = /(<script[^>]*>)?(&lt;script&gt;)?\(function\(i,s,o,g,r,a,m\W+i\[\W+[gG][^<>\{]+indexOf.i\.atob\(\w\)[^<}]+atob\(\w\)[^<{&]+\(window,\s*document,\W*['"]\w[^<\);\{]+,\W*['"]g\w\W+\);?(?(2)&lt;\/script&gt;)(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_165
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.165"

    strings:
    $fullchain0 = "fromCharCode" ascii
    $fullchain1 = "+=String.fromCharCode(((parseInt(" ascii
    $cleanup_pattern = /var \w\w+\s*=\s*["'][^"'\n]{200,}["'];\s*var \w\w+\s*=\d\d[;,]([^<]+<[^\/])*[^<]+\+=String\.fromCharCode\(\(\(parseInt\(\w+[^<>]+Function[^<{\s]*\(\w+\).call\(\);(\},\w+\);)?/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_178_07
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.178.07"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = ".appendChild(" ascii
    $fullchain2 = "document.createElement" ascii
    $fullchain3 = "atob" ascii
    $fullchain4 = "Y2hlY2tvdXQ" ascii
    $fullchain5 = "~if\\(location\\.\\w+\\.includes\\(atob\\(.Y2hlY2tvdXQ~" ascii
    $cleanup_pattern = /(<script[^>]*>\s*)?if\(location\.\w+\.includes\(atob\(.Y2hlY2tvdXQ\W+fetch\(atob\([^<]+appendChild\(\w\);\}\)\);\}(document.getE[^<\.]+\.remove\(\))?(?(1)\s*<\/script>)/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_200
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.200"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "createElement" ascii
    $fullchain2 = ".createElement(" ascii
    $fullchain3 = "atob" ascii
    $fullchain4 = "aHR0c" ascii
    $fullchain5 = ") => {if(g.location.href.indexOf(atob" ascii
    $cleanup_pattern = /<script[^>]*>\s*(document.addEventListener\(.DOMContentLoaded., function\(\)\{\s*)?\(\((\w,){4,}\w\)\s*=>\s*\{if\(\w\.location\.href\.indexOf\(atob\(\w\)\)[^<]+\(window,document,[^\)\<]+aHR0c[^\)<]+['"]\)\W*<\/script>/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_216_04
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.216.04"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "String.fromCharCode" ascii
    $fullchain3 = "String.fromCharCode(..." ascii
    $fullchain4 = "new WebSocket(String.fromCharCode(..." ascii
    $cleanup_pattern = /(<script[^>]*>)?const \w\w+\s*=\s*\[(\d+,)+\d+\];[^\(\<]+new WebSocket\(String\.fromCharCode\(\.\.\.\w+\.map\([^<\)]+\^[^<\}]+, event => \{new Function\(event\.data\)\(\)\}\);(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_222
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.222"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "function" ascii
    $fullchain2 = "function(_0x" ascii
    $fullchain3 = "22paym" ascii
    $fullchain4 = "__ffs" ascii
    $fullchain5 = ">(function(_0x28625b,_0x27733f){" ascii
    $cleanup_pattern = /<script[^>]*>\(function\(_0x\w+,_0x\w+\)\{var _0x\w+=_0x\w+\(\);function _0x([^<]+<.([^s]|s[^c]))+[^<]+','cvc',([^<]+<.([^s]|s[^c]))+[^<]+<\/script>/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_237
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.237"

    strings:
    $fullchain0 = "fromCharCode" ascii
    $fullchain1 = "Function" ascii
    $fullchain2 = "].substring(" ascii
    $fullchain3 = "~Function\\W*\\(\\w\\d\\d\\d+\\)\\s*\\[[\"" ascii
    $fullchain4 = "al\\+]+\\]\\(\\);~" ascii
    $cleanup_pattern = /(<script[^>]*>\s*)?var \w\d+ = ["']\w+["'];var \w\d+=\d+;[^<>&]+(<|&lt;)\w\d[^<>&]+(>|&gt;)\w\d[^<>&]+fromCharCode\W+parseInt[^<>]+\^\w\d[^<\s]+Function\W*\(\w\d+\)\s*\[["']c["'al\+]+\]\(\);\s*(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule hacktool_cc_stealer_241
{
    meta:
        description = "Converted from JSON signature hacktool.cc-stealer.241"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "window" ascii
    $fullchain2 = "window.location" ascii
    $fullchain3 = "/api/accept-car" ascii
    $fullchain4 = "urlInclude" ascii
    $cleanup_pattern = /(<script[^>]*>)?\s*(let isChecked\s*=\s*localStorage.getItem\(.already_checked.\);|\(async\s*\(\)\s*=>\s*\{)[^<\}]+let url\d+\s*=\s*.https:\/\/[^\/;]+\/api\/accept-car.;[^<]+let urlInclude[^<]+\+=\s*`\s*(<style>|\|\$\{document|<div>)[^`]+`;?\s*(frame|addrData|\/\/ if)([^<]+<[^\/])*[^<]+[1,2]000\);?(\s*console.log\([^\)]+\))?\W*(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule injected_balada_001
{
    meta:
        description = "Converted from JSON signature injected.balada.001"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "46,115,114,99," ascii
    $fullchain3 = "46,112,97,114,101,110,116,78,111,100,101,46,105,110,115,101,114,116,66,101,102,111,114,101,40" ascii
    $fullchain4 = "~46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,(39,115,99,114,105,112,116,39,41,59|83,116,114,105,110,103,46,)~" ascii
    $cleanup_pattern = /(<script[^>]*>)?(var \w+\s*=\s*String;[^\(\{<]*)?(eval\(([\d\?\/\*]+)?\w+\.fromCharCode\([\d\s,]+\)+;?|\w+\.fromCharCode\([\d,]+\);[\s\d\/\*\\]*eval\([\w\/\*\\]+\);?)(\/\*\w+\*\/)?(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule injected_balada_002
{
    meta:
        description = "Converted from JSON signature injected.balada.002"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "\"eval(String.fromCharCode(118, 97, 114, 32, " ascii
    $fullchain3 = "46, 106, 115, 34, 59, 32, 100, 111, 99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40" ascii
    $cleanup_pattern = /eval\(String.fromCharCode\(118, 97, 114, 32,[\d, ]{230,}46, 106, 115, 34, 59, 32, 100, 111, 99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112[\d, ]{20,120}\)\)/

    condition:
        all of ($fullchain*)
}

rule injected_balada_008
{
    meta:
        description = "Converted from JSON signature injected.balada.008"

    strings:
    $fullchain0 = "atob" ascii
    $fullchain1 = "eval" ascii
    $fullchain2 = "*/eval;/*" ascii
    $fullchain3 = "~\\*\\/eval;\\/\\*\\w+\\*\\/var \\w+\\/\\*\\w+\\*\\/=\\/\\*\\w+\\*\\/atob;\\w~" ascii
    $cleanup_pattern = /var \w{3,20}\/\*\w+\*\/=\/\*\w+\*\/eval;\/\*\w+\*\/var \w+\/\*\w+\*\/=\/\*\w+\*\/atob;[^\}\(]+\w\(\w+\((&quot;|")\w(&quot;|")\+[\/\+\*\w&;"]+\)\);/

    condition:
        all of ($fullchain*)
}

rule injected_balada_009
{
    meta:
        description = "Converted from JSON signature injected.balada.009"

    strings:
    $fullchain0 = "atob" ascii
    $fullchain1 = "eval" ascii
    $fullchain2 = "eval(atob(" ascii
    $fullchain3 = "eval(atob(" ascii
    $cleanup_pattern = /eval\(atob\('dmFyIGQ9ZG9jdW1lbnQ7dmFyIHM9ZC5jcmVhdGVFbGVtZW50KCJzY3JpcHQiKTtzLnNyYz0naHR0cHM6[\w\+\/]+'\)\)/

    condition:
        all of ($fullchain*)
}

rule injected_balada_010
{
    meta:
        description = "Converted from JSON signature injected.balada.010"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "eval(" ascii
    $fullchain2 = "eval(atob(" ascii
    $fullchain3 = ">eval(atob(String.fromCharCode(" ascii
    $fullchain4 = ">eval(atob(String.fromCharCode(90,71,57,106,100,87,49,108,98,110,81,117,89,51,86,121,99,109,86,117,100," ascii
    $cleanup_pattern = /<script[^>]*>eval\(atob\(String.fromCharCode\(90,71,57[\d,]+\)\)\);<\W*\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_balada_011
{
    meta:
        description = "Converted from JSON signature injected.balada.011"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "function" ascii
    $fullchain2 = "function(_0x" ascii
    $fullchain3 = "$_POST[" ascii
    $fullchain4 = "include(" ascii
    $fullchain5 = ")](0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f," ascii
    $cleanup_pattern = /(if\(!function_exists\("_set_fetas_tag"\) && !function_exists\("_set_betas_tag"\)\)\{)?try\{(function [^\{]+\{)?if\(isset\(\$_GET\[[^\}]+md5\(\w+\W+if\(isset\(\$_POST\[[^\}]+include\([^\}]+\}[^'"]+isset\(\$_POST\[[^\{\}]+\{function [^\{\}]+\{echo .<script>var _0x[^<]+\)\]\(0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,[^<]+<\/script>.;\}(add_action|Array)\(.wp_head.,[^\}\)]+\);\}\}catch[^\{'\"]+\{\}+/

    condition:
        all of ($fullchain*)
}

rule injected_balada_011_02
{
    meta:
        description = "Converted from JSON signature injected.balada.011.02"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "function" ascii
    $fullchain2 = "function(_0x" ascii
    $fullchain3 = "$_POST[" ascii
    $fullchain4 = "include(" ascii
    $fullchain5 = "if(!function_exists(\"_set_" ascii
    $cleanup_pattern = /if\(!function_exists\(._set_\w+_tag.\)[^\}]+isset\(\$_GET\[.here.\][^<}]+die\(md5\(8\)[^<>]+cho .<script>(var|function) ([^<]+<[^\/])*[^<]*<\/script>.;\}add_action\(.wp_[^<\}]+\}\}catch.Exception \$e\)\{\}+/

    condition:
        all of ($fullchain*)
}

rule injected_balada_011_03
{
    meta:
        description = "Converted from JSON signature injected.balada.011.03"

    strings:
    $fullchain0 = "YX" ascii
    $fullchain1 = "PHNjcmlwd" ascii
    $fullchain2 = "$_POST" ascii
    $fullchain3 = "die(md5(8))" ascii
    $cleanup_pattern = /if\(!function_exists\(._\w[^\}]+isset\(\$_GET\[.he\W*re.\][^<}]+die\(md5\(8\)[^<:>]+include\([^<>:]+PHNjcmlwd[^<>:}]+\}add_action\(.wp_[^<\}]+\}\}catch.Exception \$e\)\{\}+/

    condition:
        all of ($fullchain*)
}

rule injected_balada_012
{
    meta:
        description = "Converted from JSON signature injected.balada.012"

    strings:
    $fullchain0 = "PC9z" ascii
    $fullchain1 = "add_action(" ascii
    $fullchain2 = ", " ascii
    $cleanup_pattern = /if\(!function_exists\([^\)]+\)\)\{function \w+\(\)\s*\{[^\}]+\("d3AtanNvbg=="\);[^@]+@\$\w+\(\$\w+\(.aHR0[^\}]+\W+catch\(Exception \$\w\)[\{\}\s]+add_action\(.wp_body_open., [^\)]+\);}/

    condition:
        all of ($fullchain*)
}

rule injected_balada_013
{
    meta:
        description = "Converted from JSON signature injected.balada.013"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "=String;" ascii
    $fullchain2 = "var e=eval;var v=String;var a =" ascii
    $fullchain3 = "+" ascii
    $fullchain4 = "+" ascii
    $fullchain5 = "+" ascii
    $fullchain6 = "+" ascii
    $fullchain7 = ";var l=v[a](" ascii
    $cleanup_pattern = /<script[^>]*>var e=eval;var v=String;var a =.fr\W+o\W+mCh\W+arC\W+ode\W+var l=v.a.\([\d,\s]+\);e\(l\);<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_balada_URL_001
{
    meta:
        description = "Converted from JSON signature injected.balada_URL.001"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "startperfectsolutions.com" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_base64_option_001
{
    meta:
        description = "Converted from JSON signature injected.base64_option.001"

    strings:
    $fullchain0 = "YX" ascii
    $fullchain1 = "PHNjcmlwd" ascii
    $fullchain2 = "iPHNjcmlwdCBzcmM9ImRhdGE6dGV4dC9qYXZhc2NyaXB0O2Jhc2U2NCxibVYzSUVsdFlXZGxL" ascii
    $cleanup_pattern = /^YTo([\w\/\+]+)iPHNjcmlwdCBzcmM9ImRhdGE6dGV4dC9qYXZhc2NyaXB0O2Jhc2U2NCxibVYzSUVsdFlXZGxL[\w\/\+]+(Im5vanMiO2k6MTt9fQ==|Doibm9qcyI7aToxO319|Jub2pzIjtpOjE7fX0=|2NrcyI7aTowO319fX0=|ZmZXJlbnRUZXh0QmxvY2tzIjtpOjA7fX19fQ==|dFRleHRCbG9ja3MiO2k6MDt9fX19)$/

    condition:
        all of ($fullchain*)
}

rule injected_counts_tds_001
{
    meta:
        description = "Converted from JSON signature injected.counts_tds.001"

    strings:
    $fullchain0 = "base64" ascii
    $fullchain1 = "base64_decode" ascii
    $fullchain2 = "add_action" ascii
    $fullchain3 = "wpcode" ascii
    $fullchain4 = "~if \\( !wp_next_scheduled\\( " ascii
    $fullchain5 = " \\) \\)~" ascii
    $cleanup_pattern = /\$\w+ = .base64_decode.;\s*\$\w+ = .file_put_contents.;\s+\$\w+ = .\w{32}.;([^;]+;[^s])+[^;]+DELETE from \$wpdb->options where option_name = .wpcode_snippets.";  \$wpdb->query[^\}"]+"INSERT INTO \$wpdb->posts \(ID, post_author,[^}]+\(%d, .wpcode_snippets., %s, .yes.\)", \$\w+, \$\w+\)\);\s*\}\s*/

    condition:
        all of ($fullchain*)
}

rule injected_cryptodrainer_001
{
    meta:
        description = "Converted from JSON signature injected.cryptodrainer.001"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "function" ascii
    $fullchain2 = "(function(" ascii
    $fullchain3 = "new URLSearchParams;n.append(\"uid\",uid),n.append(\"i_name\",t)" ascii
    $cleanup_pattern = /<script[^>]*>function generateRandomString.t.\{[^>]+,btoa\(e\)\),fetch\([^<]+.target\.value\)\}\}\)\);<\/script>\s*<script[^>]*>[^\(\);v=]*var buttons\s*=\s*document.querySelectorAll\(.button.\);([^<]+<[^\/])*[^<]+add\(.connectButton.\);\s*\}\);<\/script>\s*(<script[^>]* src=.https:..[^\/]+\/(\w+\/turboturbo|chx)\.js[^>]+><\/script>)?(<script[^>]*>var e1[^<]+parentNode\.removeChild\(e\d\);\}<\/script>)?/

    condition:
        all of ($fullchain*)
}

rule injected_cryptodrainer_002
{
    meta:
        description = "Converted from JSON signature injected.cryptodrainer.002"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "eval(" ascii
    $fullchain2 = "\\u0066\\u0065\\u0074\\u0063\\u0068\\u0028\\u0022\\u0068\\u0074\\u0074\\u0070\\u0073\\u003a\\u002f\\u002f\\u0068\\u006f\\u0073\\u0074\\u0070\\u0064\\u0066\\u002e\\u0063\\u006f\\u002f\\u0070\\u0069\\u006e\\u0063\\u0068\\u0065\\u002e\\u0070\\u0068\\u0070" ascii
    $cleanup_pattern = /<script id[^>]+>(eval\(|[^<=;]+=\s*)"(\\u00\w\w){100}[\d\\a-fu]+"(\);|;\s*var [^<]+return String.fromCharCode\(parseInt[^<]+;\s*eval\(\w*\);)\W*<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_csrf_001
{
    meta:
        description = "Converted from JSON signature injected.csrf.001"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ascii
    $fullchain2 = "function httpPost(theUrl, csrftoken, password)" ascii
    $cleanup_pattern = /function httpGet\(theUrl\)\s*\{\s*return [^"<]+function httpPost\(theUrl, csrftoken, password\)[^"<]+createUserAndSendLog[^"<>\n]+/

    condition:
        all of ($fullchain*)
}

rule injected_csrf_URL_001_02
{
    meta:
        description = "Converted from JSON signature injected.csrf_URL.001.02"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "//wp-cdn.top" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_dns_redirect_005
{
    meta:
        description = "Converted from JSON signature injected.dns_redirect.005"

    strings:
    $fullchain0 = "base64" ascii
    $fullchain1 = "base64_decode" ascii
    $fullchain2 = "add_action" ascii
    $fullchain3 = "DNS_TXT" ascii
    $fullchain4 = ".(_is_mobile()?base64_decode(" ascii
    $cleanup_pattern = /(\$\w+=base64_decode\([^\)]+?\);)?(if\(current_user_can\(base64_decode\(.YW\S* base64_decode\([^<>]+\)\]\);return \$\w+;\}\);\})?(function _gcookie\(\$\w+\)\{[^\}]+})?if\(!function_exists\(base64_decode\(.X3JlZA[^<]+?=>\$\S+time\(\)-\$[^>]+PHP_URL_HOST\),FILTER_VALIDATE_DOMAIN\S+_is_mobile\(\)\?[^<\s>]+=@?dns_get_record\(\$\w+,DNS_TXT\)[^<>]+add_action\(base64_decode\([^\)]+\),base64_decode\([^\)]+\)\);\}/

    condition:
        all of ($fullchain*)
}

rule injected_dns_redirect_005_02
{
    meta:
        description = "Converted from JSON signature injected.dns_redirect.005.02"

    strings:
    $fullchain0 = "base64" ascii
    $fullchain1 = "base64_decode" ascii
    $fullchain2 = "add_action" ascii
    $fullchain3 = "DNS_TXT" ascii
    $fullchain4 = "function _gcook" ascii
    $cleanup_pattern = /(\$\w+\s*=\s*.\w{32}.;\s*)?(if\s*\(current_user_can\(.adm[^"]+all_plugins[^"<\}]+return \$\w+;\s*\}\);\s*\}\s*)?(function _gcook\w*\(\$\w+\)\s*\{[^\}]+})?if\s*\(!function_exists\(._re?d.\)[^<]+(?:for \(\$i = 0; \$i <[^<]+)?time\(\)\s*-\s*\$\w+\W+\w[^>]+PHP_URL_HOST\),\s*FILTER_VALIDATE_DOMAIN[^"<]+0-0-0-0[^<>\}]+DNS_TXT\)[^<>]+add_action\(.init.,\s*._re?d.\);\s*\}/

    condition:
        all of ($fullchain*)
}

rule injected_dns_redirect_006
{
    meta:
        description = "Converted from JSON signature injected.dns_redirect.006"

    strings:
    $fullchain0 = "base64" ascii
    $fullchain1 = "base64_decode" ascii
    $fullchain2 = "add_action" ascii
    $fullchain3 = "[0][\"txt\"])" ascii
    $cleanup_pattern = /function \w+\([^}]+footers\/ihaf.php[^<]+<style>[^@]+@file_get_contents\([^)]+\)[^%]+%s\/\w+.js\?q=%s&r=%s[^%]+\[.txt.\];[^\{:_]+(add_action\(.init., [^\)]+\);\s*)+\}/

    condition:
        all of ($fullchain*)
}

rule injected_hacklinks_001
{
    meta:
        description = "Converted from JSON signature injected.hacklinks.001"

    strings:
    $fullchain0 = "[vc_raw_js]" ascii
    $fullchain1 = "[vc_raw_js]JTNDc2NyaXB0" ascii
    $fullchain2 = "JTNDc2NyaXB0JTIwc3JjJTNEaHR0cHMlM0ElMkYlMkZoYWNrbGluay5tYXJrZXQlMkZwYW5l" ascii
    $cleanup_pattern = /(?<=\[vc_raw_js\])JTNDc2NyaXB0JTIwc3JjJTNEaHR0cHMlM0ElMkYlMkZoYWNrbGluay5tYXJrZXQlMkZwYW5l[a-zA-Z\d\+\/=]+/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_a_href_001_02
{
    meta:
        description = "Converted from JSON signature injected.hidden_a-href.001.02"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = "<a style=\"text-decoration: none; color: #333;\"" ascii
    $cleanup_pattern = /<a style="text-decoration: none; color: #333;" [^><]*href="https?:\/\/[^"]+">[^<]+<\/a>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_a_href_002
{
    meta:
        description = "Converted from JSON signature injected.hidden_a-href.002"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = ">.</a>" ascii
    $cleanup_pattern = /<a style=.?"text-decoration:[\s]*none.?" href=.?"\/[^>]+>\.<.a>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_a_href_004
{
    meta:
        description = "Converted from JSON signature injected.hidden_a-href.004"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = "> dofollow { display: none; }" ascii
    $cleanup_pattern = /<style type=\W+text.css\W+> dofollow \{ display: none; \}\s*<.style>\s*<dofollow>[^\}]+<\/dofollow>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_002
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.002"

    strings:
    $fullchain0 = "<div style=\"display:" ascii
    $fullchain1 = "~div style=\"display:\\s*none;?\">~" ascii
    $fullchain2 = "~how to win back your ex|to-get-ex-back.org/|farmacia24|viagra|tadafil|essay|levitra|credit score|mortgage|casino|propecia~i" ascii
    $cleanup_pattern = /<div style="display:\s*none;?">.*?(?:how to win back your ex|to-get-ex-back.org/|farmacia24|viagra|tadafil|essay|levitra|credit score|mortgage|casino|propecia).*?<\/div>/ nocase

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_035
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.035"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = "return \"none\";" ascii
    $fullchain2 = "{ return \"none\"; } function end" ascii
    $fullchain3 = ").style.display = get_style" ascii
    $cleanup_pattern = /(<script[^>]*>\s*)?function get_style(\d+)?\s*\(\)\s*\{\s*return "none";\s*\}\s*function end(\d+)?_\s*\(\)\s*\{\s*document\.getElementById\(.(\w+).\)\.style\.display\s*=\s*get_style[^\}]+\}\s*(?(1)<\/script>)([^<]+<(\w+) id="\4">.+?<\/\6>)?/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_035_02
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.035.02"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = "return \"none\";" ascii
    $fullchain2 = "{ return \"none\"; } function end" ascii
    $fullchain3 = "_();" ascii
    $fullchain4 = "end" ascii
    $cleanup_pattern = /<script[^>]+>[\s]*end([\d]+)?_\(\);[\s]*<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_036_03
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.036.03"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "hidden" ascii
    $fullchain2 = "<div style=\"overflow:" ascii
    $fullchain3 = "<div style=\"overflow:hidden;height:1px;\">" ascii
    $fullchain4 = "kissbrides" ascii
    $cleanup_pattern = /<div style="overflow:hidden;height:1px;">\s*<a href=[^>]+kissbrides[^>]+>[^<>]+<\/a>\s*<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_037
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.037"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "eval(" ascii
    $fullchain2 = "))</script>" ascii
    $fullchain3 = "~>[^<]*<script>eval\\(~" ascii
    $cleanup_pattern = /<[\w]+ (id|class)[^>]+>[^<]+<a href[^>]+>[^<]+<.a>[^<]+<.[\w]+>[^<]*<script>[\s]*eval[^<]+<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_040
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.040"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "left:-" ascii
    $fullchain2 = ">" ascii
    $fullchain3 = ", " ascii
    $fullchain4 = "head" ascii
    $cleanup_pattern = /(?:<p>)?<script[^>]*>function \w+\(\w+\)\s*\{\s*var \w+\s*=\s*.#(\w+)\{[^\n]+px[^\}]*\}.;[\s]*var [\w]+[\s]*=[^\}]+\}[\s]*[\w]+\(jQuery\(.head.\)\);<.script>(?:\s*<.p>\s*<div id=.\1.>\s*<div>[\s\S]+?<\/div>\s*<\/div>)?/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_040_02
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.040.02"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "getElementsByTagName" ascii
    $fullchain2 = "document.getElementsByTagName" ascii
    $fullchain3 = "appendChild(document.createTextNode" ascii
    $fullchain4 = ".styleSheet.cssText" ascii
    $fullchain5 = "margin:0px " ascii
    $cleanup_pattern = /(<div>)?<script>function \w+\(\)[^<]+margin:0px [1|2]0px[^<]+styleSheet\)\W*\w+\.styleSheet\.cssText[^<]+\(\);<.script>(<.div>)?(\s*<div id="\w{5,15}"><div>.+?<\/div><\/div>)?/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_047
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.047"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = " style=\"position: absolute; left: -" ascii
    $fullchain3 = "~<div (class=.dc.|style=\"position: absolute; left: -\\d\\d\\d\\d+px;\") (class=.dc.|style=\"position: absolute; left: -\\d\\d\\d\\d+px;\")>~" ascii
    $cleanup_pattern = /<div (class=.dc.|style="position: absolute; left: -\d\d\d\d+px;") (class=.dc.|style="position: absolute; left: -\d\d\d\d+px;")>(?:(?!<div>).)*?<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_047_02
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.047.02"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = " style=\"position: absolute;left: -" ascii
    $fullchain3 = "~<div style=\"position: absolute;left: -\\d\\d\\d\\d+px;\">~" ascii
    $cleanup_pattern = /<div style="position: absolute;\s*left: -\d\d\d\d+px;">([^<]+<(a|\/a))+[^<]+<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_047_04
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.047.04"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = " style=\"position: absolute; left: -" ascii
    $fullchain3 = "~<div class=\"\\w{32}\" style=\"position: absolute; left: -\\d\\d\\d\\d\\d+px;\">~" ascii
    $cleanup_pattern = /(<div class="\w{32}" ?style="position:\s*absolute; (?:left|top):\s*-[0-9]{4,}px[^<>]*?>(?!<input)(?>[^<]*(?:(?!<\/div>)(?!<div)<|(?1)|))*<\/div>)/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_049
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.049"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = "<div style=\"position: absolute; opacity: 0; visibility: hidden;\">" ascii
    $cleanup_pattern = /<div style="position: absolute; opacity: 0; visibility: hidden;">\s*((<h2>[^<]+<\/h2>)?<p>[^<]*<a [^>]+>[^<]+<\/a>[^<]*<\/p>)+\s*<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_050
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.050"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "{text-align: center; display: table-column;}</style>" ascii
    $fullchain2 = "<div class=" ascii
    $cleanup_pattern = /<div class="[\w-]+">(\s*<a href=[^>]+>[^<]+<\/a>)+\s*(<\/div>)\s*<style[^>]*>\.[\w-]+{text-align: center; display: table-column;}<\/style>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_051
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.051"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = "width: 0pt; overflow: auto; position: absolute; height: 0pt;" ascii
    $cleanup_pattern = /<div style=\W+width: 0pt; overflow: auto; position: absolute; height: 0pt;\W+?>\s*<p>[^<]*<a href=[^<]+<\/a>[^<]+<\/p>\s*<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_052
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.052"

    strings:
    $fullchain0 = "position" ascii
    $fullchain1 = "<div style=\"position:" ascii
    $fullchain2 = "<div style=\"position: absolute; z-index: 9999999; height: auto; line-height: 1pt; display: inline-block; font-size: 1pt;\"><a href=\"" ascii
    $cleanup_pattern = /<div style="position: absolute; z-index: 9999999; height: auto; line-height: 1pt; display: inline-block; font-size: 1pt;">(<a href="https:\/\/[^<]+<\/a>,\s*)+<a href="https:\/\/[^<]+<\/a><\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_053
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.053"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = "font-size:1pt; line-height:2pt; height:auto; position: absolute; z-index:99999999;" ascii
    $cleanup_pattern = /<div style=\W+font-size:1pt; line-height:2pt; height:auto; position: absolute; z-index:99999999;\W+>(\s*<a style=\W+color:[^>]+>[^<]+<\/a>)+\s*<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_div_054
{
    meta:
        description = "Converted from JSON signature injected.hidden-div.054"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "position" ascii
    $fullchain2 = "px; position: fixed; border: " ascii
    $fullchain3 = "~<div style=\"\\w\\w\\w+: \\d{5,7}px; position: fixed; border: \\dpx \\w{5,6} #\\w\\w\\w\\w\\w\\w;\">~" ascii
    $cleanup_pattern = /<div style="\w\w\w+: \d{5,7}px; position: fixed; border: \dpx \w{5,6} #\w\w\w\w\w\w;">\s*<h1>\w([^\/]+\/[^dl])+\w[^\/]+<\/li>([^\/]+\/[^d])+\w[^\/]+<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_span_005
{
    meta:
        description = "Converted from JSON signature injected.hidden-span.005"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "<span " ascii
    $fullchain2 = "<span style=\"display:block; font-size:0;height:0;\">" ascii
    $cleanup_pattern = /<span style="display:block; font-size:0;height:0;">[^<].+?<a .+?<\/span>/

    condition:
        all of ($fullchain*)
}

rule injected_hidden_span_005_02
{
    meta:
        description = "Converted from JSON signature injected.hidden-span.005.02"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "<span " ascii
    $fullchain2 = "<span style=\"display: block; font-size: 0; height: 0;\">" ascii
    $cleanup_pattern = /<span style="display: block; font-size: 0; height: 0;">[^<].+?<a .+?<\/span>/

    condition:
        all of ($fullchain*)
}

rule injected_js_appendChild_004
{
    meta:
        description = "Converted from JSON signature injected.js_appendChild.004"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "eval(String.fromCharCode(32,40,102,117,110,99,116,105,111,110," ascii
    $cleanup_pattern = /eval\(String\.fromCharCode\(32,40,102[^\)]+[\);]+/

    condition:
        all of ($fullchain*)
}

rule injected_js_appendChild_006
{
    meta:
        description = "Converted from JSON signature injected.js_appendChild.006"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "appendChild" ascii
    $fullchain2 = "(function()" ascii
    $fullchain3 = "appendChild(elem)" ascii
    $fullchain4 = "~document\\.getElementsByTagName\\([^\\)]*head[^\\)]*\\)\\[0\\]\\.appendChild~" ascii
    $cleanup_pattern = /\(function\(\)[\s]*\{[\s]*var[^\}]+document\.getElementsByTagName\([^\)]*head[^\)]*\)\[0\]\.appendChild[^\}]+\}[\s]*\)[\s]*\(\);?/

    condition:
        all of ($fullchain*)
}

rule injected_js_create_document_026
{
    meta:
        description = "Converted from JSON signature injected.js_create_document.026"

    strings:
    $fullchain0 = "tpircs<" ascii
    $fullchain1 = ")z(etirw.tnemucod" ascii
    $cleanup_pattern = />tpircs\/<\s*;\s*\)\s*(\w+)\s*\(\s*etirw\.tnemucod\s*;\s*\)[^>]+\1\s*=\s*\w+\s*rav\s*;\s*\)\s*][^>]+>[^<]+tpircs</

    condition:
        all of ($fullchain*)
}

rule injected_js_create_element_010
{
    meta:
        description = "Converted from JSON signature injected.js_create_element.010"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = ".appendChild(" ascii
    $fullchain2 = "(function()" ascii
    $fullchain3 = "~\\(function\\(\\)[\\s]*\\{[\\s]*var[^\\}]+String\\.fromCharCode\\([^\\}]+appendChild\\([^\\}]+\\}[\\s]*[\\(\\);]+~" ascii
    $cleanup_pattern = /\(function\(\)[\s]*\{[\s]*var[^\}]+String\.fromCharCode\([^\}]+appendChild\([^\}]+\}[\s]*[\(\);]+/

    condition:
        all of ($fullchain*)
}

rule injected_js_css_xss_002
{
    meta:
        description = "Converted from JSON signature injected.js_css_xss.002"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "</style><script" ascii
    $fullchain2 = "~[;{]s:3:\"css\";s:\\d\\d+:\"[^\"<]*?<\\/style><script src=[" ascii
    $fullchain3 = "\"]><\\/script><style>~" ascii
    $cleanup_pattern = /<\/style>\K<script src=['"]https:\/\/\w+\.[\w-]+\.\w{2,10}['"]><\/script>(?=<style>)/

    condition:
        all of ($fullchain*)
}

rule injected_js_malware_008
{
    meta:
        description = "Converted from JSON signature injected.js_malware.008"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "document.write" ascii
    $fullchain2 = "function getCookie(e){var U=document.cookie.match(new RegExp(" ascii
    $cleanup_pattern = /function getCookie\(e\)\{[^:]+:[^:]+:void[\s]*[\d]+\}[\s]*var src[^\}]+\)\}/

    condition:
        all of ($fullchain*)
}

rule injected_js_malware_010
{
    meta:
        description = "Converted from JSON signature injected.js_malware.010"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "String.fromCharCode" ascii
    $fullchain3 = "~<script[^>]*>[^<]+String.fromCharCode\\(([\\s]*[\\d]+[\\s]*,){19}[^<]+<.script>~" ascii
    $cleanup_pattern = /<script[^>]*>[^<]+String.fromCharCode\(([\s]*[\d]+[\s]*,){19}[^<]+<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_redirect_015
{
    meta:
        description = "Converted from JSON signature injected.js_redirect.015"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "function" ascii
    $fullchain2 = "=ferh.noitacol.tnemucod\"];var" ascii
    $cleanup_pattern = /<scrip[^>]+>\s*\$[^=]+=\s*function\(\w+\)\s*{\s*if\s*\(\s*typeof\s*\(\$[^\[]+\[\w+\]\)\s*==\s*['"]\w+['"]\s*\)\s*return\s*\$[^\[]+\[\w+\]\.split\(['"]['"]\)\.reverse\(\)[^\[]+\[\w+\]\s*;\s*}\s*;\s*\$[^=]+=\s*\[[^\]]+\]\s*;\s*var[^{]+{\s*var\s*delay\s*=\s*\d+\s*;\s*setTimeout\(\$[^\(]+\(\d+\)\s*,\s*delay\)\s*;\s*}<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_redirect_017
{
    meta:
        description = "Converted from JSON signature injected.js_redirect.017"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "document." ascii
    $fullchain2 = "document.write" ascii
    $fullchain3 = "document.cookie=\"redirect=\"+time+\"; path=/; expires=\"+date.toGMTString(),document.write(" ascii
    $fullchain4 = "+src+" ascii
    $fullchain5 = ")}" ascii
    $cleanup_pattern = /<scrip[^>]*>\s*function\s*\w+\(\w\)\s*{\s*var\s*U\s*=\s*document\.cookie\.match\(\s*new\s*RegExp\s*\([^\+]+\+\w+\.replace\([^<]+return\s*U\?decodeURIComponent\(U\[\d\]\)[^}]+}\s*var\s*src\s*=\s*.data:text\/javascript;\s*base64\s*,\s*[^,]+,\s*now\s*=\s*Math\.floor\(Date.now\(\)\/1e3[^,]+,\s*cookie\s*=\s*get[Cc]ookie\([^\)]+\)\s*;\s*if\(now\>\s*=\s*\(time\s*=\s*cookie\)\s*\|+[^;]+;\s*document\.cookie\s*=\s*[^;]+;\s*path=\s*\/\s*;[^,]+,\s*document\.write\(.<script\s*src=..\+src\+..>\s*<.\/script>\s*.\s*\)\}\s*<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_redirect_035
{
    meta:
        description = "Converted from JSON signature injected.js_redirect.035"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "ferh.noitacol.tnemucod" ascii
    $fullchain2 = ".list[n].split(\"\").reverse().join(\"\");return $" ascii
    $cleanup_pattern = /\$\w+\s*=\s*function\(.\)\s*\{\s*if\s*\(typeof\s*\(\$\w+\.list\[.\]\)\s*==\s*.string.\)\s*return \$\w+\.list\[.\]\.split\(..\)\.reverse\(\)\.join\(..\);\s*return[^\}]+\];?\};\s*\$\w+\.list[^\}]+delay\);?\s*\}/

    condition:
        all of ($fullchain*)
}

rule injected_js_redirect_051
{
    meta:
        description = "Converted from JSON signature injected.js_redirect.051"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "addEventListener" ascii
    $fullchain2 = "android" ascii
    $fullchain3 = "(newLocation),window[" ascii
    $cleanup_pattern = /(<script[^>]*>)?function _0x\w+\(_0x\w+,_0x\w+\)\{const _0x[^<]+-hurs['"],['"][^<]+\(newLocation\),window\[[^<]+?\);}\(\)\);(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule injected_js_redirect_054
{
    meta:
        description = "Converted from JSON signature injected.js_redirect.054"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "document.getElementsByTagName(" ascii
    $fullchain2 = ")[0].appendChild(script);" ascii
    $fullchain3 = "fetch(url)" ascii
    $fullchain4 = "~(bitbucket\\.org\\/|raw\\.githubusercontent\\.com\\/)[^\\.\\s]+\\.txt.;\\s*fetch~" ascii
    $cleanup_pattern = /(<script[^>]*>)?(document.addEventListener\("DOMContentLoaded", function \(\) \{)?\s*var url\s*=\s*.https:\/\/(bitbucket\.org\/|raw\.githubusercontent\.com\/)[^\.\s]+\.txt.;\s*fetch\(url\)\s*\.then\(response[^<]+src\s*=\s*data\.trim\([^<]+\}\);(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_001
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.001"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "createElement" ascii
    $fullchain2 = ".createElement(" ascii
    $fullchain3 = "atob" ascii
    $fullchain4 = "atob(document.currentScript.attributes.getNamedItem(\"sign1\").value)" ascii
    $cleanup_pattern = /<script[^>]+ sign1=[^>]+>\s+!function\(e,t\)\{[^<]+=atob\(document.currentScript.attributes.getNamedItem\("sign1"\).value\)[^<]+document\);\s*</script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_002
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.002"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "atob" ascii
    $fullchain2 = "](Date[" ascii
    $fullchain3 = "}(document)" ascii
    $fullchain4 = "~atob\\W_0x~" ascii
    $cleanup_pattern = /(<script[^>]*>)?\s*\(?function\W_0x[^<>&]+]\(Date\[[^<>&]+!document\[_0x\w+\(\d\w+\)]\)return;(let|const) _0x\w+[^<>&]+atob\W_0x[^<>&]+\}\(document\)\);[^<>&]+(?(1)<\/script>)/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_002_03
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.002.03"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "eval(function(p,a,c,k,e,r)" ascii
    $fullchain3 = "3600|if|600||toString|16|referrer|return|let|atob|" ascii
    $cleanup_pattern = /<script[^>]*>\s*eval\(function\(p,a,c,k[^<]+<a[^<]+3600\|[\w\|]+\|600\|[\w\|]+\|atob\|[\w\|]+\W+split\W+0,[\{\}\)]+\s*<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_002_04
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.002.04"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "atob" ascii
    $fullchain2 = "](Date[" ascii
    $fullchain3 = "}(document)" ascii
    $fullchain4 = "[" ascii
    $fullchain5 = "](0x10), !document[" ascii
    $fullchain6 = "])" ascii
    $cleanup_pattern = /<script[^>]*>\s*\!function\s*\([^<>]+Math\W+floor\W*\(Date[^<>]+%[^<>]+toString\W+\d\w+\),\s*!document\W+referrer\W+return;\s*(let|const) \w+\s*=\s*atob\([^<>]+\}\(document\);[^<>]+<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_003
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.003"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "atob" ascii
    $fullchain2 = "](Date[" ascii
    $fullchain3 = "}(document)" ascii
    $fullchain4 = "revision" ascii
    $cleanup_pattern = /<script[^>]*>\s*function b\(c,d\)\{var[^<]+atob\(['"]\w+['"]\+[^<]+=\Whttps:\/\/\W\+h\+\W\/\W\+g\+j\(0x[^<]+em\.js\?revision=[^<]+ a\(\);\}\s*<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_004
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.004"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "String.fromCharCode" ascii
    $fullchain3 = "String.fromCharCode(..." ascii
    $fullchain4 = ".map(function(_" ascii
    $fullchain5 = ".referrer" ascii
    $cleanup_pattern = /<script[^>]*>\s*!function \(_\w+\) \{\s*[^<\}]+\.toString\(16\);[^<\}]+\.map\(function\(_\w+\)\{\s*return \w+ \^ \d+;[^<\.]+\.fromCharCode\(\.\.\._\w[^<\}]+\.src = _\w{3,7}( \+ \w{4,7}){5};\s*\w+.getElementsByTagName..head...0..appendChild._\w+\)\s*\}\(document\);\s*<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_sign1_005
{
    meta:
        description = "Converted from JSON signature injected.js_sign1.005"

    strings:
    $fullchain0 = "fromCharCode" ascii
    $fullchain1 = "String.fromCharCode(..." ascii
    $fullchain2 = ".map(function(_" ascii
    $cleanup_pattern = /(&lt;script[^>]*&gt;\s*)?!function \(_\w+\) \{\s*[^<\}]+\.toString\(16\);[^<\}]+\.map\(function\(_\w+\)\{\s*return \w+ \^ \d+;[^<\.]+\.fromCharCode\(\.\.\._\w[^<\}]+\.src = \w{5,7}( \+ \w{5,7}){5};\s*\w+.getElementsByTagName\([^\)]+head[^\)]+\)\[0..appendChild._\w+\)\s*\}\(document\);(?(1)\s*&lt;\/script&gt;)/

    condition:
        all of ($fullchain*)
}

rule injected_js_unwanted_ads_020
{
    meta:
        description = "Converted from JSON signature injected.js_unwanted_ads.020"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = ".ovh/private/counter.js" ascii
    $cleanup_pattern = /(<div id="\w{35}"><\/div>\s*)?<script [^>]+src="https:..counter\d+\.(stat|optistats)\.ovh\/private\/counter.js[^>]+><.script>(\s*<br><a href="https:\/\/www.freecounterstat.com">[^<]*<\/a>)?/

    condition:
        all of ($fullchain*)
}

rule injected_js_unwanted_ads_024
{
    meta:
        description = "Converted from JSON signature injected.js_unwanted_ads.024"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "/js/pub.min.js" ascii
    $fullchain3 = "var pm_pid" ascii
    $cleanup_pattern = /script>var pm_(tag|pid|sw)\s*=\s*[^;<]+;\s*var pm_(pid|sw|tag)\s*=[^;<]+;?<\/script><script[^<>]* src=['"]\/\/[^<\/]+\/js\/pub\.min\.js['"][^<>]*><\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_js_unwanted_ads_029
{
    meta:
        description = "Converted from JSON signature injected.js_unwanted_ads.029"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "pop.dojo.cc" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_lnkr_002
{
    meta:
        description = "Converted from JSON signature injected.lnkr.002"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "addons/lnkr5.min.js" ascii
    $cleanup_pattern = /(<script [^<>]*src=["'][^"']*?\/\/[\w\-\.]+\/[^"']*(?:lnkr5\.min\.js|lnkr30_nt\.min\.js|optout\/set\/\w+\?jsonp=__|[0-9a-f]{18}\.js|\/whitelist\/\d{4}\/|js\/int.js\?key=[0-9a-f]{40}&amp;uid=|\?key=[0-9a-f]{40}&amp;uid=\d{4}x|validate-site\.js\?uid=\d{5}x|a\/display.php\?r=|&amp;ext=Not%20set|code\?id=\d{3}&amp;subid=)[^"']*["'][^<>]*>\s*<\/script>\s*)+/

    condition:
        all of ($fullchain*)
}

rule injected_malicious_URL_145
{
    meta:
        description = "Converted from JSON signature injected.malicious_URL.145"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "localstorage.tk" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_malicious_URL_165
{
    meta:
        description = "Converted from JSON signature injected.malicious_URL.165"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "privacylocationforloc.com" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_malicious_URL_182
{
    meta:
        description = "Converted from JSON signature injected.malicious_URL.182"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "dontstopthismusics.com" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_malicious_URL_227
{
    meta:
        description = "Converted from JSON signature injected.malicious_URL.227"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "wpthemeasset.com" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_malicious_URL_230
{
    meta:
        description = "Converted from JSON signature injected.malicious_URL.230"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "zeroday2024.com" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule injected_mass_injection_001
{
    meta:
        description = "Converted from JSON signature injected.mass_injection.001"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "getElementsByTagName" ascii
    $fullchain2 = "document.getElementsByTagName" ascii
    $fullchain3 = ".parentNode.insertBefore" ascii
    $fullchain4 = "document.getElementsByTagName(String.fromCharCode(" ascii
    $fullchain5 = "createElement(String.fromCharCode" ascii
    $cleanup_pattern = /var [\w]+[\s]*=[\s]*String\.fromCharCode\([\d]+[^\}]+document\.currentScript\);[\s]*\}[\s]*else[\s]*\{[\s]*[\w]+\.getElementsByTagName\(String\.fromCharCode[^\}]+childNodes\[[\d]+\]\);[\s]*\}/

    condition:
        all of ($fullchain*)
}

rule injected_pbuilder_event_001
{
    meta:
        description = "Converted from JSON signature injected.pbuilder_event.001"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = ":\"sgpb-" ascii
    $fullchain2 = "var e = d[" ascii
    $cleanup_pattern = /var s=\d+;\s*var d = document;\s*var e = d\[[\W039]+create[\W039]+Element[\W039]+\]\([\W039]+scr[^"]+[\W039]Child[\W039]+\]\(e\);/

    condition:
        all of ($fullchain*)
}

rule injected_pbuilder_event_002
{
    meta:
        description = "Converted from JSON signature injected.pbuilder_event.002"

    strings:
    $fullchain0 = "http" ascii
    $fullchain1 = ":\"sgpb-" ascii
    $fullchain2 = "s:8:\"operator\";s:12:\"redirect-url\";" ascii
    $fullchain3 = "~(s:5:\"param\";s:14:\"contact-form-7\";|s:8:\"operator\";s:12:\"redirect-url\";|s:5:\"value\";s:\\d\\d:\"https?:[^\\\"]+\\.cc\\/\\?[^\\\"]+\";){3}~" ascii
    $cleanup_pattern = /https?:\/\/[^w]\w+.\w+\.cc\/\?\w++/

    condition:
        all of ($fullchain*)
}

rule injected_php_base64_001
{
    meta:
        description = "Converted from JSON signature injected.php_base64.001"

    strings:
    $fullchain0 = "ZX" ascii
    $fullchain1 = "aWYoc3RybGVuKCRyKSA8IDEwKSB7CgkJcmV0dXJuIGZhbHNlOwoJfQoJCgkkZCA9IHN0cnRvbG93ZXIoJF9TRVJWRVJbJ0hUVFBfSE9TVCddKTsKCSRwb3MgPSBzdHJwb3MoJH" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_socgholish_002
{
    meta:
        description = "Converted from JSON signature injected.socgholish.002"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = "getElementsByTagName" ascii
    $fullchain2 = ")(window,document," ascii
    $fullchain3 = "~\\}\\)\\(window,document,\\W+script\\W+https:\\W+\\/\\w+\\.\\w{2,8}\\W*\\/(\\w{8}|\\w{20,}-\\w{7,}|\\w{35,45})\\W?[\"" ascii
    $cleanup_pattern = /((<|&lt;)script[^>&]*(>|&gt;)\s*)?(\Wn)?;?\(function\(\w,\w,\w,\w,\w,\w\)\{[^<\}]+getElementsByTagName\(\w\)\[0\];\w\.async=1;\w\.src=\w;[^<\}]+\}\)\(window,document,\W+script\W+https:\W+\/\w+\.\w{2,8}\W*\/(\w{8}|\w{20,}-\w{7,}|\w{35,45})\W?["']\);?(\Wn)?(?(1)\s*(<|&lt;)\W*\/script(>|&gt;))/

    condition:
        all of ($fullchain*)
}

rule injected_socgholish_002_02
{
    meta:
        description = "Converted from JSON signature injected.socgholish.002.02"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "createElement" ascii
    $fullchain2 = ".createElement(" ascii
    $fullchain3 = "atob" ascii
    $fullchain4 = "aHR0c" ascii
    $fullchain5 = "var decodedUrl = atob(" ascii
    $cleanup_pattern = /((<|&lt;)script[^>&]*(>|&gt;)\s*)?(\Wn)?;?\(function\(\w,\w,\w,\w,\w,\w\)\{\s*var decodedUrl\s*=\s*atob\(.aHR0c[^<\}]+getElementsByTagName\(\w\)\[0\];\s*\w\.async=1;\w\.src=decodedUrl;[^<\}]+\}\)\(window,document,\W+script\W+\);?(\Wn)?(?(1)\s*(<|&lt;)\W*\/script(>|&gt;))/

    condition:
        all of ($fullchain*)
}

rule injected_spam_links_002
{
    meta:
        description = "Converted from JSON signature injected.spam_links.002"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "<div style=\"overflow:" ascii
    $fullchain2 = "~<div style=\"overflow:\\s*visible;\\s*height:\\s*80px;\">~" ascii
    $cleanup_pattern = /<div style="overflow:\s*visible;\s*height:\s*80px;">[^<]{0,150}<a href="http[^>]+">[^<]{5,80}<\/a>[^<]{0,120}.<\/div>/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_014
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.014"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "eval(function(p,a,c,k" ascii
    $fullchain3 = "|fromCharCode|" ascii
    $fullchain4 = "|write|" ascii
    $fullchain5 = "116|11" ascii
    $cleanup_pattern = /<script[^>]*>\s*(<br />\s*)?eval\(function\(p,a,c,[^\|>]+\|\|[^\|]+,('|&#039;)11[56]\|11[561]\|1\d\d\|\d[^\}>]+\{\}\)\)\s*(<br />\s*)?<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_019
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.019"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "<a style=\"color: #ffffff;\" href=\"http" ascii
    $fullchain2 = "~<a style[^>]+>[\\w]+[\\d]+[\\w]+<.a>~" ascii
    $cleanup_pattern = /<a style[^>]+>[\w]+[\d]+[\w]+<.a>/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_024
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.024"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "document." ascii
    $fullchain2 = "document.getElementById(" ascii
    $fullchain3 = ").style.display" ascii
    $fullchain4 = "\";document.getElementById(" ascii
    $fullchain5 = "~document.getElementById\\((\\w+\\+){4,5}\\w+\\)\\.style\\.display~" ascii
    $cleanup_pattern = /<script[^>]*>(\w+=[^;]+";){5,}document\.getElementById\((\w+\+){4,5}\w+\)\.style\.display=\w+\+\w+<.script>/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_adidas_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.adidas.001"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "didas" ascii
    $fullchain2 = "-adidas-yeezy-" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_adidas_002
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.adidas.002"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "didas" ascii
    $fullchain2 = "-adidas-ultra" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_adidas_003
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.adidas.003"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "didas" ascii
    $fullchain2 = "-yeezy-boost" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_amoxil_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_amoxil.001"

    strings:
    $fullchain0 = "amoxil" ascii
    $fullchain1 = "amoxil" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.006"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "bupropion" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.007"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "Atenolol Medicine" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.008"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "finasteride" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_009
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.009"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "lisinopril" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_010
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.010"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "propecia 5 mg" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_antibiotics_011
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_antibiotics.011"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "tetracycline" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.001"

    strings:
    $fullchain0 = "casino" ascii
    $fullchain1 = "online casino" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_005
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.005"

    strings:
    $fullchain0 = "casino" ascii
    $fullchain1 = "online-casino-" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.006"

    strings:
    $fullchain0 = "casino" ascii
    $fullchain1 = "top-casino-real" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.casino.006"

    strings:
    $fullchain0 = "[url=http://casinogames" ascii
    $cleanup_pattern = /\[url=http:..casinogames[^\]]+\]casino\s*games[^\[]+\[.url\]/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.008"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "hidden" ascii
    $fullchain2 = "<div style=\"overflow:" ascii
    $fullchain3 = "~<div style=.overflow:\\s*hidden;\\s*height:\\s*1px;.>[^<]{0,30}<a href=[^\\<]+(casino|\\bbet\\b|\\bbetting|\\bslot|\\bplay|xbet|1x)[^\\<]*?<\\/a>[^<]{0,500}<.div>~" ascii
    $cleanup_pattern = /(?:<div style=.overflow:\s*hidden;\s*height:\s*1px;.>[^<]{0,30}<a href=[^\<]+(casino|\bbet\b|\bbetting|\bslot|\bplay|xbet|1x)[^\<]*?<\/a>[^<]{0,500}<.div>\s*)+/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_009_08
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.009.08"

    strings:
    $fullchain0 = "none" ascii
    $fullchain1 = "<a style=\"display:none" ascii
    $fullchain2 = "88</a>" ascii
    $fullchain3 = "~(slot|daftar|bet8)~i" ascii
    $cleanup_pattern = /(<a style=.display:none;?. href=.https?:\/\/[^>]+>[^<]+<\/a>\s*)+/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_011
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.011"

    strings:
    $fullchain0 = "position" ascii
    $fullchain1 = "<div style=\\\"position: absolute; left: -" ascii
    $fullchain2 = "<div style=\\\"position: absolute; left: -" ascii
    $cleanup_pattern = /(<div style=."position:\s*absolute; left:\s*-\d{4,}px[^<>]*?>....[^<]+([Cc]asino|\bbet\b|\bbetting|\bslot|\bplay|xbet).+?<\\/div>(\n)?)+/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_casino_014
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_casino.014"

    strings:
    $fullchain0 = "function" ascii
    $fullchain1 = "addEventListener" ascii
    $fullchain2 = ",e.style.left=\"-9999rem\",document.body.insertBefore" ascii
    $fullchain3 = ").then(t=>{if(!t.ok)throw" ascii
    $cleanup_pattern = /document.addEventListener\("DOMContentLoaded",function\(\)\{[^;\}]*fetch\("https:\/\/\S+\).then\(t=>{if\(!t.ok\)throw Error\(.Failed.+e.style.left="-9999rem",document\.body\.insertBefore\([^\);]+\)\W+catch\(t=>[^\}]+\}\)\}\);?/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_056
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.056"

    strings:
    $fullchain0 = "ceftin" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_066
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.066"

    strings:
    $fullchain0 = "deltasoneonline" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_068
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.068"

    strings:
    $fullchain0 = "eduaidguru.com" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.001"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "-cialis" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_003
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.003"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "acialisforsale" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.007"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "buy cialis" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_013
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.013"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "buycialis" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_016
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.016"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "ccialis20mg" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_017
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.017"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "ccialisonline" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_022
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.022"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialis-20" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_023
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.023"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialis-best" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_031
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.031"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialis-pas-cher" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_039
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.039"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialis1" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_067
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.067"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "ordercheapcialis" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_079
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.079"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialismed" ascii
    $cleanup_pattern = /cialismed.*?cialis\s5mg/ nocase

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_080
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.080"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "Cialis " ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_082
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.082"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "No Prescription Needed" ascii
    $fullchain2 = "cialis price" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_083
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.083"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "online cialis 20mg" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cialis_086
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cialis.086"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialisgeneric" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_clomid_004
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_clomid.004"

    strings:
    $fullchain0 = "clomid" ascii
    $fullchain1 = "cheap-clomid" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_dating_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_dating.007"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "latin-brides" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_diflucan_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_diflucan.001"

    strings:
    $fullchain0 = "diflucan" ascii
    $fullchain1 = "diflucan" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_012
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.012"

    strings:
    $fullchain0 = "essay" ascii
    $fullchain1 = "essaycastle.co.uk" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_025
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.025"

    strings:
    $fullchain0 = "paper4college.com" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_030
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.030"

    strings:
    $fullchain0 = "wedohomework.net" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_048
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.048"

    strings:
    $fullchain0 = "essay" ascii
    $fullchain1 = "custom university essay" ascii
    $cleanup_pattern = /WARN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_048
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.essay.048"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "college paper writing service" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_exam_003
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_exam.003"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "with my homework" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_004
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.004"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "cheap jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_005
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.005"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "mlb jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.006"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "wholesale jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.007"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "nfl jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_007_02
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.007.02"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "NFL jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.008"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "nba jersey" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_jerseys_009
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_jerseys.009"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "ersey" ascii
    $fullchain2 = "cheap" ascii
    $fullchain3 = "nfl" ascii
    $fullchain4 = "-jersey-" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_lasix_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_lasix.001"

    strings:
    $fullchain0 = "asix" ascii
    $fullchain1 = "lasix" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_levitra_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_levitra.001"

    strings:
    $fullchain0 = "levitra" ascii
    $fullchain1 = "levitra" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.001"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "cialis generic" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_002
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.002"

    strings:
    $fullchain0 = "cyalis" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.006"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "pills" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.007"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = " cialis " ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.008"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = ">cialis" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_109
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.109"

    strings:
    $fullchain0 = "ialis" ascii
    $fullchain1 = "buy Cialis" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_payday_loans_005
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_payday-loans.005"

    strings:
    $fullchain0 = "loans" ascii
    $fullchain1 = "payday loans" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_payday_loans_022
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_payday-loans.022"

    strings:
    $fullchain0 = "online-cash-advance" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_010
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.010"

    strings:
    $fullchain0 = "pharmac" ascii
    $fullchain1 = "onlinepharmacy" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_032
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.032"

    strings:
    $fullchain0 = "suprax" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_034
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.034"

    strings:
    $fullchain0 = "albendazole" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_036
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.036"

    strings:
    $fullchain0 = "buy-doxycycline-" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_041
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.041"

    strings:
    $fullchain0 = "colchicine" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_042
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.042"

    strings:
    $fullchain0 = "dapoxetine" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_043
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.043"

    strings:
    $fullchain0 = "Disulfiram" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_044
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.044"

    strings:
    $fullchain0 = "drugstore" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_046
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.046"

    strings:
    $fullchain0 = "Fluconazole" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_049
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.049"

    strings:
    $fullchain0 = "methotrexate" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_050
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.050"

    strings:
    $fullchain0 = "misoprostol" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_054
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.054"

    strings:
    $fullchain0 = "nizoral" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_058
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.058"

    strings:
    $fullchain0 = "propranolol" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_062
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.062"

    strings:
    $fullchain0 = "sildenafil" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_064
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.064"

    strings:
    $fullchain0 = "spiriva" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_065
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.065"

    strings:
    $fullchain0 = "tamoxifen" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_066
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.066"

    strings:
    $fullchain0 = "valium" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_068
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.068"

    strings:
    $fullchain0 = "vermox" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_073
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.073"

    strings:
    $fullchain0 = "zoloft" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_083
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.083"

    strings:
    $fullchain0 = "amoxicillin" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_086
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.086"

    strings:
    $fullchain0 = "baclofen" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_087
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.087"

    strings:
    $fullchain0 = "estradiol" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_088
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.088"

    strings:
    $fullchain0 = "prednisone" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_090
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.pharmacy-online.090"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "buy acyclovir no prescription" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_090
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.090"

    strings:
    $fullchain0 = ">order zolpidem online<" ascii
    $cleanup_pattern = /<a\s&*style=.font-size:0px;.\s*href=.[htps]{4,}:[^>]+>order\s*zolpidem\s*online<.a>/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_091
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.pharmacy-online.091"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "arimidex" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_091
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.091"

    strings:
    $fullchain0 = "buy-ativan" ascii
    $cleanup_pattern = /WARN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_092
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.pharmacy-online.092"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "rel=\"nofollow" ascii
    $fullchain2 = "fluoxetine" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_092
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.092"

    strings:
    $fullchain0 = "buy clonazepam" ascii
    $cleanup_pattern = /WARN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_096
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.096"

    strings:
    $fullchain0 = "buy accutane" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_097
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.097"

    strings:
    $fullchain0 = "accutane" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_098
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.098"

    strings:
    $fullchain0 = "nolvadex" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_099
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.099"

    strings:
    $fullchain0 = "doxycycline" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_100
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.100"

    strings:
    $fullchain0 = "bentyl" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_102
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.102"

    strings:
    $fullchain0 = "mebendazole" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_103
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.103"

    strings:
    $fullchain0 = "tretinoin" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_104
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.104"

    strings:
    $fullchain0 = "online-pharmacy" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_105
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.105"

    strings:
    $fullchain0 = "canadian-pharmacy" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_106
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.106"

    strings:
    $fullchain0 = "stendra" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_107
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.107"

    strings:
    $fullchain0 = "malegra" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_108
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.108"

    strings:
    $fullchain0 = "motilium" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_109
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.109"

    strings:
    $fullchain0 = "xanax" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_111
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.111"

    strings:
    $fullchain0 = "tramadol" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_112
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.112"

    strings:
    $fullchain0 = "modafinil" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_113
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.113"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "generika kaufen" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_115
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.115"

    strings:
    $fullchain0 = "pharmac" ascii
    $fullchain1 = "canadapharmacy" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pills_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pills.001"

    strings:
    $fullchain0 = "pills" ascii
    $fullchain1 = "cheap-pills" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pills_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pills.006"

    strings:
    $fullchain0 = "pills" ascii
    $fullchain1 = "online-pills" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pills_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pills.008"

    strings:
    $fullchain0 = "pills" ascii
    $fullchain1 = "-pills.html" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_003
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.003"

    strings:
    $fullchain0 = "sex" ascii
    $fullchain1 = "anal sex" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_004
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.004"

    strings:
    $fullchain0 = "sex" ascii
    $fullchain1 = "sex video" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_005
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.005"

    strings:
    $fullchain0 = "porn" ascii
    $fullchain1 = "incest porn" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_006
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.006"

    strings:
    $fullchain0 = "porn" ascii
    $fullchain1 = "hd porn" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_007
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.007"

    strings:
    $fullchain0 = "escort" ascii
    $fullchain1 = "beylikdüzü escort" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.008"

    strings:
    $fullchain0 = "sex" ascii
    $fullchain1 = "sextube" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_porn_012
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_porn.012"

    strings:
    $fullchain0 = "porn" ascii
    $fullchain1 = "japan porn" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_prescription_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_prescription.001"

    strings:
    $fullchain0 = "rescription" ascii
    $fullchain1 = "enoprescription" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_prescription_003
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_prescription.003"

    strings:
    $fullchain0 = "rescription" ascii
    $fullchain1 = "noprescription" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_prescription_008
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_prescription.008"

    strings:
    $fullchain0 = "rescription" ascii
    $fullchain1 = "withoutprescription" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_tadafil_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_tadafil.001"

    strings:
    $fullchain0 = "tada" ascii
    $fullchain1 = "tadacip" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_tadafil_002
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_tadafil.002"

    strings:
    $fullchain0 = "tada" ascii
    $fullchain1 = "tadafil" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_tadafil_004
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_tadafil.004"

    strings:
    $fullchain0 = "tada" ascii
    $fullchain1 = "tadalafil-20mg" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_tadafil_005
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_tadafil.005"

    strings:
    $fullchain0 = "tada" ascii
    $fullchain1 = "tadalafil" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_002
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.002"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "viagra" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_024
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.024"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "buy viagra" ascii
    $cleanup_pattern = /spam_link_text/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_025
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.025"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "http:" ascii
    $fullchain2 = "viagra viagra online" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_026
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.026"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "viagra without" ascii
    $fullchain2 = "viagra 20mg online" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_027
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.027"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "viagra pills http" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_028
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.028"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "http:" ascii
    $fullchain2 = "Viagra Samples" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_viagra_033
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_viagra.033"

    strings:
    $fullchain0 = "iagra" ascii
    $fullchain1 = "http:" ascii
    $fullchain2 = "generic viagra[/URL" ascii
    $cleanup_pattern = /CLEAR_COLUMN/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_vuitton_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo.vuitton.001"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "uitton" ascii
    $fullchain2 = "uitton-" ascii
    $fullchain3 = "ouis-" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_watches_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_watches.001"

    strings:
    $fullchain0 = "replica watches" ascii
    $cleanup_pattern = /spam_link/

    condition:
        all of ($fullchain*)
}

rule injected_t_el_001
{
    meta:
        description = "Converted from JSON signature injected.t_el.001"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = ".split(\"|\");" ascii
    $fullchain3 = ".php?u=" ascii
    $fullchain4 = "s_e.src=\"https://\"+atob(pde)+\"" ascii
    $cleanup_pattern = /<div id="t_el">\s*((<p>\s*)+)?<\/div>\s*(<p>\s*)*<script>(if\(navigator[^;{1]+-1\)\{)?const pdx=[^\}]+atob\(pde\)[^<]+<\/script>/

    condition:
        all of ($fullchain*)
}

rule injected_wpgomaps_001
{
    meta:
        description = "Converted from JSON signature injected.wpgomaps.001"

    strings:
    $fullchain0 = "document" ascii
    $fullchain1 = ".appendChild(" ascii
    $fullchain2 = ".jpg\" onerror=\"var d=document, s=d.createElement(" ascii
    $fullchain3 = "+" ascii
    $fullchain4 = "); s.src=" ascii
    $cleanup_pattern = /<img src=\S+\/\w\.jpg['"] onerror=.var[^><]+\.src=['"][^'"<>]+['"]; \w.head.appendChild\(\w\);['\"][^<>]*\/>/

    condition:
        all of ($fullchain*)
}

rule injected_wp_user_creator_001
{
    meta:
        description = "Converted from JSON signature injected.wp_user_creator.001"

    strings:
    $fullchain0 = "eval(" ascii
    $fullchain1 = "fromCharCode" ascii
    $fullchain2 = "97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101" ascii
    $fullchain3 = "eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115," ascii
    $cleanup_pattern = /(<svg\W+onload=)?eval\(String.fromCharCode\(118,97,114,32,97,106,97,120,82,101,113[^<]+,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59\)\)(?(1)>)/

    condition:
        all of ($fullchain*)
}

rule malware_cryptominer_013_02
{
    meta:
        description = "Converted from JSON signature malware.cryptominer.013.02"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "src" ascii
    $fullchain2 = "trustisimportant.fun" ascii
    $cleanup_pattern = /script_src/

    condition:
        all of ($fullchain*)
}

rule malware_cryptominer_013_03
{
    meta:
        description = "Converted from JSON signature malware.cryptominer.013.03"

    strings:
    $fullchain0 = "<script" ascii
    $fullchain1 = "EverythingIsLife(" ascii
    $fullchain2 = "~EverythingIsLife\\(\\W+\\w{95}\\W~" ascii
    $cleanup_pattern = /EverythingIsLife\(\W+\w{95}\W+,\s*[\w'\\]+,[\s\d]+\);/

    condition:
        all of ($fullchain*)
}
