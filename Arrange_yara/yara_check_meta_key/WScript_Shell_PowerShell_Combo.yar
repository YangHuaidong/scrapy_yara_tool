rule WScript_Shell_PowerShell_Combo {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-07"
    description = "Detects malware from Middle Eastern campaign reported by Talos"
    family = "None"
    hacker = "None"
    hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".CreateObject(\"WScript.Shell\")" ascii
    $p1 = "powershell.exe" fullword ascii
    $p2 = "-ExecutionPolicy Bypass" fullword ascii
    $p3 = "[System.Convert]::FromBase64String(" ascii
    $fp1 = "Copyright: Microsoft Corp." ascii
  condition:
    filesize < 400KB and $s1 and 1 of ($p*)
    and not 1 of ($fp*)
}