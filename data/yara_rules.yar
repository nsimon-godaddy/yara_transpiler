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


rule PHP_KingDefacer_WebShell {
    meta:
        description = "Detects KingDefacer PHP Web Shell Exploit"
        author = "Security Analyst"
        threat_level = "HIGH"
    strings:
        $signature1 = "KingDefacer" nocase
        $signature2 = "Turkish Security Network" nocase
        $php_bypass = "safe_mode" nocase
        $remote_exec = "$_GET['file']" nocase
        $exploit_marker = "This is exploit from" nocase
    condition:
        filetype == "php" and 
        (3 of ($signature1, $signature2, $php_bypass, $remote_exec, $exploit_marker))
}