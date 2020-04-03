import "pe"
rule Rehashed_RAT_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-08"
    description = "Detects malware from Rehashed RAT incident"
    family = "None"
    hacker = "None"
    hash1 = "49efab1dedc6fffe5a8f980688a5ebefce1be3d0d180d5dd035f02ce396c9966"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "dalat.dulichovietnam.net" fullword ascii
    $x2 = "web.Thoitietvietnam.org" fullword ascii
    $a1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64)" fullword ascii
    $a2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii
    $s1 = "GET /%s%s%s%s HTTP/1.1" fullword ascii
    $s2 = "http://%s:%d/%s%s%s%s" fullword ascii
    $s3 = "{521338B8-3378-58F7-AFB9-E7D35E683BF8}" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 300KB and (
    pe.imphash() == "9c4c648f4a758cbbfe28c8850d82f931" or
    ( 1 of ($x*) or 3 of them )
    ) or ( 4 of them )
}