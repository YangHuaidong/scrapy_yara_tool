rule Disclosed_0day_POCs_shellcodegenerator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-07"
    description = "Detects POC code from disclosed 0day hacktool set"
    family = "None"
    hacker = "None"
    hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed 0day Repos"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\shellcodegenerator.pdb" ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}