rule Pc_rejoice {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file rejoice.exe"
    family = "None"
    hacker = "None"
    hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
    $s2 = "http://www.xxx.com/xxx.exe" fullword ascii
    $s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
    $s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
    $s5 = "ListViewProcessListColumnClick!" fullword ascii
    $s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}