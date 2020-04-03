rule Tools_unknown {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file unknown.exe"
    family = "None"
    hacker = "None"
    hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
    $s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
    $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
    $s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
    $s5 = "Host: 127.0.0.1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}