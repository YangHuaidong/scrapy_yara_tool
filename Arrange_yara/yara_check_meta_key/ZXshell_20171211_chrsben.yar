import "pe"
rule ZXshell_20171211_chrsben {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-11"
    description = "Detects ZxShell variant surfaced in Dec 17"
    family = "None"
    hacker = "None"
    hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/snc85M"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "ncProxyXll" fullword ascii
    $s1 = "Uniscribe.dll" fullword ascii
    $s2 = "GetModuleFileNameDll" fullword ascii
    $s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and (
    pe.imphash() == "de481441d675e9aca4f20bd8e16a5faa" or
    pe.exports("PerfectWorld") or
    pe.exports("ncProxyXll") or
    1 of ($x*) or
    2 of them
}