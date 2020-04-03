rule shelltools_g0t_root_uptime {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file uptime.exe"
    family = "None"
    hacker = "None"
    hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "JDiamondCSlC~"
    $s1 = "CharactQA"
    $s2 = "$Info: This file is packed with the UPX executable packer $"
    $s5 = "HandlereateConso"
    $s7 = "ION\\System\\FloatingPo"
  condition:
    all of them
}