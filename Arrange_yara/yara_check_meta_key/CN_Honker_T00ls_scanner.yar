rule CN_Honker_T00ls_scanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
    family = "None"
    hacker = "None"
    hash = "70b04b910d82b32b90cd7f355a0e3e17dd260cb3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
    $s17 = "Team:www.t00ls.net" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 330KB and all of them
}