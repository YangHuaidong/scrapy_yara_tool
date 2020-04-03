rule kelloworld_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file kelloworld.dll"
    family = "None"
    hacker = "None"
    hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Hello World!" fullword wide
    $s2 = "kelloworld.dll" fullword ascii
    $s3 = "kelloworld de mimikatz pour Windows" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}