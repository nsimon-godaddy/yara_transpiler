/*
 * Example YARA Rules - Properly Transpiled
 * This file demonstrates best practices for YARA rule creation
 * Use these as reference for generating high-quality detection rules
 */

// ============================================================================
// PHP WEBSHELL DETECTION - GOOD EXAMPLE
// ============================================================================
rule PHP_Webshell_Good {
    meta:
        description = "Detects PHP webshell with code execution capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
        date = "2025-08-26"
        version = "1.0"
    
    strings:
        // Code execution functions - these are the actual malicious behavior
        $eval_func = "eval(" ascii
        $system_func = "system(" ascii
        $exec_func = "exec(" ascii
        $shell_exec = "shell_exec(" ascii
        $passthru_func = "passthru(" ascii
        
        // File manipulation functions
        $file_get_contents = "file_get_contents(" ascii
        $file_put_contents = "file_put_contents(" ascii
        $unlink_func = "unlink(" ascii
        $chmod_func = "chmod(" ascii
        
        // Variable access patterns
        $get_var = "$_GET[" ascii
        $post_var = "$_POST[" ascii
        $files_var = "$_FILES[" ascii
        $server_var = "$_SERVER[" ascii
        
        // File inclusion
        $include_func = "include(" ascii
        $require_func = "require(" ascii
    
    condition:
        filetype == "php" and
        // Require multiple execution functions to reduce false positives
        2 of ($eval_func, $system_func, $exec_func, $shell_exec, $passthru_func) and
        // Require file operations or variable access
        (2 of ($file_get_contents, $file_put_contents, $unlink_func, $chmod_func) or
         2 of ($get_var, $post_var, $files_var, $server_var))
}

// ============================================================================
// PHP BACKDOOR DETECTION - GOOD EXAMPLE
// ============================================================================
rule PHP_Backdoor_Good {
    meta:
        description = "Detects PHP backdoor with remote access capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        // Remote code execution
        $eval_remote = "eval($_POST" ascii
        $eval_get = "eval($_GET" ascii
        $eval_request = "eval($_REQUEST" ascii
        
        // File upload patterns
        $file_upload = "move_uploaded_file(" ascii
        $tmp_name = "$_FILES['file']['tmp_name']" ascii
        
        // Command execution
        $cmd_exec = "cmd" ascii
        $shell_exec = "shell_exec(" ascii
        
        // Anti-detection
        $ignore_abort = "ignore_user_abort(" ascii
        $time_limit = "set_time_limit(" ascii
    
    condition:
        filetype == "php" and
        // Must have remote code execution
        (1 of ($eval_remote, $eval_get, $eval_request)) and
        // Plus additional malicious behavior
        (1 of ($file_upload, $shell_exec, $ignore_abort))
}

// ============================================================================
// EXECUTABLE MALWARE DETECTION - GOOD EXAMPLE
// ============================================================================
rule Executable_Malware_Good {
    meta:
        description = "Detects malicious executable with suspicious behavior"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        // Suspicious API calls
        $create_process = "CreateProcess" ascii
        $create_thread = "CreateThread" ascii
        $virtual_alloc = "VirtualAlloc" ascii
        $write_process = "WriteProcessMemory" ascii
        
        // Network activity
        $winsock = "WSAStartup" ascii
        $socket = "socket(" ascii
        $connect = "connect(" ascii
        $send = "send(" ascii
        
        // File operations
        $create_file = "CreateFile" ascii
        $write_file = "WriteFile" ascii
        $delete_file = "DeleteFile" ascii
        
        // Registry access
        $reg_open = "RegOpenKey" ascii
        $reg_set = "RegSetValue" ascii
    
    condition:
        // Must be executable
        uint16(0) == 0x5a4d and  // MZ header
        // Require multiple suspicious behaviors
        3 of ($create_process, $create_thread, $virtual_alloc, $write_process) and
        2 of ($winsock, $socket, $connect, $send) and
        2 of ($create_file, $write_file, $delete_file)
}

// ============================================================================
// DOCUMENT MALWARE DETECTION - GOOD EXAMPLE
// ============================================================================
rule Document_Malware_Good {
    meta:
        description = "Detects malicious document with embedded payloads"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        // Office document markers
        $office_header = "PK" ascii
        $word_doc = "[Content_Types].xml" ascii
        $excel_doc = "xl/workbook.xml" ascii
        
        // Suspicious content
        $vba_code = "VBA" ascii
        $macro_code = "Macro" ascii
        $powershell = "powershell" nocase
        $cmd_shell = "cmd.exe" ascii
        
        // Embedded payloads
        $base64_payload = "base64" ascii
        $hex_payload = "0x" ascii
        $url_payload = "http://" ascii
    
    condition:
        // Must be a document
        uint16(0) == 0x4b50 and  // PK header
        // Require suspicious content
        (1 of ($vba_code, $macro_code)) and
        (2 of ($powershell, $cmd_shell, $base64_payload, $hex_payload, $url_payload))
}

// ============================================================================
// SCRIPT MALWARE DETECTION - GOOD EXAMPLE
// ============================================================================
rule Script_Malware_Good {
    meta:
        description = "Detects malicious scripts with execution capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        // PowerShell execution
        $powershell_exe = "powershell.exe" ascii
        $powershell_ps1 = "powershell" ascii
        $bypass_policy = "ExecutionPolicy" ascii
        $bypass_amsi = "amsi" ascii
        
        // Command execution
        $cmd_exec = "cmd.exe" ascii
        $wscript = "wscript" ascii
        $cscript = "cscript" ascii
        
        // Suspicious functions
        $invoke_expression = "Invoke-Expression" ascii
        $iex = "iex" ascii
        $start_process = "Start-Process" ascii
        
        // Network activity
        $web_client = "WebClient" ascii
        $download_file = "DownloadFile" ascii
        $download_string = "DownloadString" ascii
    
    condition:
        // Must be a script file
        (file_extension == ".ps1" or file_extension == ".vbs" or file_extension == ".js") and
        // Require execution capabilities
        (2 of ($powershell_exe, $powershell_ps1, $cmd_exec, $wscript, $cscript)) and
        // Plus suspicious behavior
        (2 of ($invoke_expression, $iex, $start_process, $web_client, $download_file))
}

// ============================================================================
// ARCHIVE MALWARE DETECTION - GOOD EXAMPLE
// ============================================================================
rule Archive_Malware_Good {
    meta:
        description = "Detects malicious archives with embedded payloads"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        // Archive headers
        $zip_header = "PK" ascii
        $rar_header = "Rar!" ascii
        $tar_header = "ustar" ascii
        
        // Suspicious file names
        $exe_in_archive = ".exe" ascii
        $dll_in_archive = ".dll" ascii
        $scr_in_archive = ".scr" ascii
        $bat_in_archive = ".bat" ascii
        
        // Malicious content indicators
        $autorun = "autorun.inf" ascii
        $desktop_ini = "desktop.ini" ascii
        $thumbs_db = "thumbs.db" ascii
    
    condition:
        // Must be an archive
        (uint16(0) == 0x4b50 or uint32(0) == 0x21726152) and  // PK or Rar!
        // Must contain suspicious files
        2 of ($exe_in_archive, $dll_in_archive, $scr_in_archive, $bat_in_archive) and
        // Plus suspicious content
        1 of ($autorun, $desktop_ini, $thumbs_db)
}

/*
 * KEY PRINCIPLES FOR GOOD YARA RULES:
 * 
 * 1. FOCUS ON BEHAVIOR, NOT TEXT:
 *    - Use function names, API calls, variable patterns
 *    - Avoid descriptive text strings that change frequently
 *    - Look for actual malicious capabilities
 * 
 * 2. REDUCE FALSE POSITIVES:
 *    - Require multiple conditions to match
 *    - Use file type checks (filetype, uint16/uint32 headers)
 *    - Balance sensitivity with specificity
 * 
 * 3. USE PROPER YARA SYNTAX:
 *    - Correct string definitions with modifiers (ascii, nocase)
 *    - Logical conditions with 'and', 'or', 'of' operators
 *    - Proper meta information
 * 
 * 4. AVOID COMMON PITFALLS:
 *    - No unsupported regex patterns
 *    - No backreferences
 *    - No overly broad string patterns
 *    - No reliance on file size alone
 * 
 * 5. PRIORITIZE DETECTION:
 *    - Focus on what the malware DOES, not what it SAYS
 *    - Look for execution patterns, not documentation
 *    - Use technical indicators over descriptive text
 */
