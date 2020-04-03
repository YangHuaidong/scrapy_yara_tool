rule xscan_gui {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file xscan_gui.exe"
    family = "None"
    hacker = "None"
    hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
    $s2 = "www.target.com" fullword ascii
    $s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
    $s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}