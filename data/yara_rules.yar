rule backdoor_curl_002
{
    meta:
        description = "Converted from JSON signature backdoor.curl.002"

    strings:
    $fullchain0 = "AfterFilterCallbac" ascii
    $fullchain1 = "curl${IFS%??}-" ascii

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

    condition:
        all of ($fullchain*)
}

rule duplicate_injected_spam_seo_casino_006
{
    meta:
        description = "Converted from JSON signature duplicate_injected.spam-seo.casino.006"

    strings:
    $fullchain0 = "[url=http://casinogames" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_056
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.056"

    strings:
    $fullchain0 = "ceftin" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_066
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.066"

    strings:
    $fullchain0 = "deltasoneonline" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_cheap_buys_068
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_cheap-buys.068"

    strings:
    $fullchain0 = "eduaidguru.com" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_025
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.025"

    strings:
    $fullchain0 = "paper4college.com" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_essay_030
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_essay.030"

    strings:
    $fullchain0 = "wedohomework.net" ascii

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

    condition:
        all of ($fullchain*)
}

rule duplicate_injected_spam_seo_essay_048
{
    meta:
        description = "Converted from JSON signature duplicate_injected.spam-seo.essay.048"

    strings:
    $fullchain0 = " href" ascii
    $fullchain1 = "college paper writing service" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_link_002
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_link.002"

    strings:
    $fullchain0 = "cyalis" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_payday_loans_022
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_payday-loans.022"

    strings:
    $fullchain0 = "online-cash-advance" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_032
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.032"

    strings:
    $fullchain0 = "suprax" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_034
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.034"

    strings:
    $fullchain0 = "albendazole" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_036
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.036"

    strings:
    $fullchain0 = "buy-doxycycline-" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_041
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.041"

    strings:
    $fullchain0 = "colchicine" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_042
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.042"

    strings:
    $fullchain0 = "dapoxetine" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_043
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.043"

    strings:
    $fullchain0 = "Disulfiram" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_044
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.044"

    strings:
    $fullchain0 = "drugstore" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_046
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.046"

    strings:
    $fullchain0 = "Fluconazole" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_049
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.049"

    strings:
    $fullchain0 = "methotrexate" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_050
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.050"

    strings:
    $fullchain0 = "misoprostol" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_054
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.054"

    strings:
    $fullchain0 = "nizoral" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_058
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.058"

    strings:
    $fullchain0 = "propranolol" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_062
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.062"

    strings:
    $fullchain0 = "sildenafil" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_064
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.064"

    strings:
    $fullchain0 = "spiriva" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_065
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.065"

    strings:
    $fullchain0 = "tamoxifen" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_066
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.066"

    strings:
    $fullchain0 = "valium" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_068
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.068"

    strings:
    $fullchain0 = "vermox" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_073
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.073"

    strings:
    $fullchain0 = "zoloft" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_083
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.083"

    strings:
    $fullchain0 = "amoxicillin" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_086
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.086"

    strings:
    $fullchain0 = "baclofen" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_087
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.087"

    strings:
    $fullchain0 = "estradiol" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_088
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.088"

    strings:
    $fullchain0 = "prednisone" ascii

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

    condition:
        all of ($fullchain*)
}

rule duplicate_injected_spam_seo_pharmacy_online_090
{
    meta:
        description = "Converted from JSON signature duplicate_injected.spam-seo_pharmacy-online.090"

    strings:
    $fullchain0 = ">order zolpidem online<" ascii

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

    condition:
        all of ($fullchain*)
}

rule duplicate_injected_spam_seo_pharmacy_online_091
{
    meta:
        description = "Converted from JSON signature duplicate_injected.spam-seo_pharmacy-online.091"

    strings:
    $fullchain0 = "buy-ativan" ascii

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

    condition:
        all of ($fullchain*)
}

rule duplicate_injected_spam_seo_pharmacy_online_092
{
    meta:
        description = "Converted from JSON signature duplicate_injected.spam-seo_pharmacy-online.092"

    strings:
    $fullchain0 = "buy clonazepam" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_096
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.096"

    strings:
    $fullchain0 = "buy accutane" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_097
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.097"

    strings:
    $fullchain0 = "accutane" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_098
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.098"

    strings:
    $fullchain0 = "nolvadex" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_099
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.099"

    strings:
    $fullchain0 = "doxycycline" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_100
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.100"

    strings:
    $fullchain0 = "bentyl" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_102
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.102"

    strings:
    $fullchain0 = "mebendazole" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_103
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.103"

    strings:
    $fullchain0 = "tretinoin" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_104
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.104"

    strings:
    $fullchain0 = "online-pharmacy" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_105
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.105"

    strings:
    $fullchain0 = "canadian-pharmacy" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_106
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.106"

    strings:
    $fullchain0 = "stendra" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_107
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.107"

    strings:
    $fullchain0 = "malegra" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_108
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.108"

    strings:
    $fullchain0 = "motilium" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_109
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.109"

    strings:
    $fullchain0 = "xanax" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_111
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.111"

    strings:
    $fullchain0 = "tramadol" ascii

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_pharmacy_online_112
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_pharmacy-online.112"

    strings:
    $fullchain0 = "modafinil" ascii

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

    condition:
        all of ($fullchain*)
}

rule injected_spam_seo_watches_001
{
    meta:
        description = "Converted from JSON signature injected.spam-seo_watches.001"

    strings:
    $fullchain0 = "replica watches" ascii

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

    condition:
        all of ($fullchain*)
}


rule memWebshell {
    meta:
        description = "Detects PHP webshell with remote code execution and suspicious system modifications"
        author = "Security Analyst"
        severity = "CRITICAL"
        category = "MALWARE"
    strings:
        $php_header = "<?php" ascii
        $chmod_func = "chmod(" ascii
        $unlink_func = "unlink(" ascii
        $eval_func = "eval(" ascii
        $file_get_contents = "file_get_contents(" ascii
        $remote_url = "http://" ascii
        $ignore_abort = "ignore_user_abort(" ascii
        $set_time_limit = "set_time_limit(" ascii
        $sleep_func = "sleep(" ascii
    condition:
        $php_header and
        $chmod_func and
        $unlink_func and
        $eval_func and
        $file_get_contents and
        $remote_url and
        $ignore_abort and
        $set_time_limit and
        $sleep_func
}