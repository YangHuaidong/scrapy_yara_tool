rule PasswordsPro {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-27"
    description = "Auto-generated rule - file PasswordsPro.exe"
    family = "None"
    hacker = "None"
    hash1 = "5b3d6654e6d9dc49ee1136c0c8e8122cb0d284562447abfdc05dfe38c79f95bf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "PasswordPro"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "No users marked for attack or all marked users already have passwords found!" fullword ascii
    $s2 = "%s\\PasswordsPro.ini.Dictionaries(%d)" fullword ascii
    $s3 = "Passwords processed since attack start:" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 2000KB and
    1 of them
}