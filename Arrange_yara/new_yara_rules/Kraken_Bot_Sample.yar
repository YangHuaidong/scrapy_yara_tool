rule Kraken_Bot_Sample {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-07"
    description = "Kraken Bot Sample - file inf.bin"
    family = "None"
    hacker = "None"
    hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "%s=?getname" fullword ascii
    $s4 = "&COMPUTER=^" fullword ascii
    $s5 = "xJWFwcGRhdGElAA=" fullword ascii /* base64 encoded string '%appdata%' */
    $s8 = "JVdJTkRJUi" fullword ascii /* base64 encoded string '%WINDIR' */
    $s20 = "btcplug" fullword ascii
  condition:
    uint16(0) == 0x5a4d and all of them
}