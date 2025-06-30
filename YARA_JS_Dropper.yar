rule JS_PowerShell_Dropper_Generic
{
    meta:
        description = "Generic JavaScript/HTA PowerShell dropper using ActiveX and obfuscated download technique"
        author = "IRNinja"
        date = "2025-06-29"

    strings:
        $activex = "ActiveXObject" nocase
        $createObj = "CreateObject" nocase
        $wscript = "WScript.Shell" nocase

        $powershell = "powershell" nocase
        $bits = "Start-BitsTransfer" nocase
        $expand = "Expand-Archive" nocase
        $exe = ".exe Start" nocase

        $http = "http://" nocase
        $jpg = ".jpg" nocase
        $zip = ".zip" nocase
        $public = "Users\\Public" nocase

        $obf1 = "gNKQu"
        $obf2 = "clkPy"

    condition:
        all of ($activex, $createObj, $wscript) and
        2 of ($powershell, $bits, $expand, $exe) and
        2 of ($http, $jpg, $zip, $public) and
        any of ($obf*)
}
