rule WMImplant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-24"
    description = "Auto-generated rule - file WMImplant.ps1"
    family = "None"
    hacker = "None"
    hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Invoke-ProcessPunisher -Creds $RemoteCredential" fullword ascii
    $x2 = "$Target -query \"SELECT * FROM Win32_NTLogEvent WHERE (logfile='security')" ascii
    $x3 = "WMImplant -Creds" fullword ascii
    $x4 = "-Download -RemoteFile C:\\passwords.txt" ascii
    $x5 = "-Command 'powershell.exe -command \"Enable-PSRemoting" fullword ascii
    $x6 = "Invoke-WMImplant" fullword ascii
  condition:
    1 of them
}