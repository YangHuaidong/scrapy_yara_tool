rule DragonFly_APT_Sep17_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-12"
    description = "Detects malware from DrqgonFly APT report"
    family = "None"
    hacker = "None"
    hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" fullword wide
    $s2 = "C:\\Users\\Public\\Log.txt" fullword wide
    $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword wide
    $s4 = "***************** Mozilla Firefox ****************" fullword wide
    $s5 = "********************** Opera *********************" fullword wide
    $s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" fullword wide
    $s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" fullword wide
    $s8 = "**************** Internet Explorer ***************" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them )
}