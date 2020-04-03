rule GoodToolset_pr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file pr.exe"
    family = "None"
    hacker = "None"
    hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-->Got WMI process Pid: %d " ascii
    $s2 = "-->This exploit gives you a Local System shell " ascii
    $s3 = "wmiprvse.exe" fullword ascii
    $s4 = "Try the first %d time" fullword ascii
    $s5 = "-->Build&&Change By p " ascii
    $s6 = "root\\MicrosoftIISv2" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}