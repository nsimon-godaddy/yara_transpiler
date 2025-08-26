

rule AK_74 {
    meta:
        description = "Detects PHP webshell with advanced execution capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "WEBSHELL"
    strings:
        $session_start = "session_start()" ascii
        $error_reporting_disable = "error_reporting(0)" ascii
        $time_limit_disable = "set_time_limit(0)" ascii
        $dangerous_functions = /\b(eval|system|exec|shell_exec|passthru)\s*\(/ ascii
        $file_operations = /\b(opendir|readdir|filesize|filemtime)\s*\(/ ascii
        $server_var = "$_SERVER" ascii
        $session_var = "$_SESSION" ascii
    condition:
        filetype == "php" and
        (2 of ($session_start, $error_reporting_disable, $time_limit_disable)) and
        (2 of ($dangerous_functions, $file_operations)) and
        ($server_var or $session_var)
}