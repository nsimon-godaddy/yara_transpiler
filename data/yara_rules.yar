

rule memWebshell {
    meta:
        description = "Detects PHP remote code execution and system modification malware"
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
        $sleep_func = "sleep(" ascii
        $ignore_abort = "ignore_user_abort(" ascii
        $set_time_limit = "set_time_limit(" ascii
    condition:
        $php_header at 0 and
        $chmod_func and
        $unlink_func and
        $eval_func and
        $file_get_contents and
        $remote_url and
        $sleep_func and
        $ignore_abort and
        $set_time_limit
}

rule file_529 {
    meta:
        description = "Detects PHP webshell with bypass and file manipulation capabilities"
        author = "Security Analyst"
        severity = "CRITICAL"
        category = "WEBSHELL"
    strings:
        $php_header = "<?php" ascii
        $safe_mode_bypass = "safe_mode and open_basedir Bypass" ascii
        $get_post_file = "$_GET['file']" ascii
        $post_file = "$_POST['file']" ascii
        $server_vars = "$_SERVER[\"HTTP_HOST\"]" ascii
        $server_script = "$_SERVER[\"SCRIPT_NAME\"]" ascii
        $file_manipulation = "htmlspecialchars(" ascii
        $form_injection = "<form name=\"form\" action=\"" ascii
        $dangerous_funcs = "eval(" ascii nocase
        $shell_exec = "shell_exec(" ascii nocase
    condition:
        $php_header at 0 and 
        $safe_mode_bypass and
        (
            $get_post_file or 
            $post_file
        ) and
        2 of ($server_vars, $server_script, $file_manipulation, $form_injection) and
        1 of ($dangerous_funcs, $shell_exec)
}