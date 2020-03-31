rule HKTL_Lazagne_Gen_18 {
  meta:
    author = Spider
    comment = None
    date = 2018-12-11
    description = Detects Lazagne password extractor hacktool
    family = 18
    hacker = None
    hash1 = 51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/AlessandroZ/LaZagne
    score = 80
    threatname = HKTL[Lazagne]/Gen.18
    threattype = Lazagne
  strings:
    $x1 = "lazagne.config.powershell_execute(" fullword ascii
    $x2 = "creddump7.win32." ascii
    $x3 = "lazagne.softwares.windows.hashdump" ascii
    $x4 = ".softwares.memory.libkeepass.common(" ascii
  condition:
    2 of them
}