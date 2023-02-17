rule suspicious_reg_exe_export
{
    meta:
        description = "Detects suspicious reg.exe processes and exports to Excel"
        author = "Your Name"
    
    strings:
        $reg_exe = "reg.exe"
        $suspicious_args = /(?:add|copy|delete|load|hivelist|query|save|unload|import|export).*software\\(wow6432node\\)?\\(?:classes\\|microsoft\\|sysinternals\\)/i
        $cmd_output = /.*>(.*)\.xlsx/i
    
    condition:
        $reg_exe in (process_name, command_line) and $suspicious_args at 1 and $cmd_output
}

