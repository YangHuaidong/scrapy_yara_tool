rule PLUGIN_AJunk {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file AJunk.dll"
    family = "None"
    hacker = "None"
    hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "AJunk.dll" fullword ascii
    $s2 = "AJunk.DLL" fullword wide
    $s3 = "AJunk Dynamic Link Library" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 560KB and all of them
}