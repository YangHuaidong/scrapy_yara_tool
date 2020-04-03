rule Explosion_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/03"
    description = "Explosion/Explosive Malware - Volatile Cedar APT"
    family = "None"
    hacker = "None"
    hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/5vYaNb"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
    $s9 = "WinAutologon From Winlogon Reg" fullword ascii
    $s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
    $s11 = "IE:Password-Protected sites" fullword ascii
    $s12 = "\\his.sys" fullword ascii
    $s13 = "HTTP Password" fullword ascii
    $s14 = "\\data.sys" fullword ascii
    $s15 = "EL$_RasDefaultCredentials#0" fullword wide
    $s17 = "Office Outlook HTTP" fullword ascii
    $s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii
  condition:
    all of them and
    uint16(0) == 0x5A4D
}