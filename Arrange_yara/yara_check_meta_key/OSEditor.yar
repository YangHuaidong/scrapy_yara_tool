rule OSEditor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file OSEditor.exe"
    family = "None"
    hacker = "None"
    hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "OSEditor.exe" fullword wide
    $s2 = "netsafe" wide
    $s3 = "OSC Editor" fullword wide
    $s4 = "GIF89" ascii
    $s5 = "Unlock" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}