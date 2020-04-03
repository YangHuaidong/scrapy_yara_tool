rule CN_Tools_PcShare {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file PcShare.exe"
    family = "None"
    hacker = "None"
    hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
    $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
    $s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
    $s5 = "port=%s;name=%s;pass=%s;" fullword wide
    $s16 = "%s\\ini\\*.dat" fullword wide
    $s17 = "pcinit.exe" fullword wide
    $s18 = "http://www.pcshare.cn" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}