rule x64_KiwiCmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file KiwiCmd.exe"
    family = "None"
    hacker = "None"
    hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
    $s2 = "Kiwi Cmd no-gpo" fullword wide
    $s3 = "KiwiAndCMD" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}