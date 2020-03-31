rule mswin_check_lm_group {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file mswin_check_lm_group.exe
    family = group
    hacker = None
    hash = 115d87d7e7a3d08802a9e5fd6cd08e2ec633c367
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = mswin[check]/lm.group
    threattype = check
  strings:
    $s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
    $s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
    $s3 = "-D    default user Domain" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 380KB and all of them
}