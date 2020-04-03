rule CN_Tools_VNCLink {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file VNCLink.exe"
    family = "None"
    hacker = "None"
    hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\temp\\vncviewer4.log" fullword ascii
    $s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
    $s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}