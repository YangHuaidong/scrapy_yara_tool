rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-10"
    description = "Detects a web shell"
    family = "None"
    hacker = "None"
    hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/bartblaze/PHP-backdoors"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
    $s2 = "input[type=text], input[type=password]{" fullword ascii
  condition:
    ( uint16(0) == 0x6c3c and filesize < 80KB and all of them )
}