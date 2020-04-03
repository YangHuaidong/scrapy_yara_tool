rule epathobj_exp64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file epathobj_exp64.exe"
    family = "None"
    hacker = "None"
    hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
    $s2 = "Exploit ok run command" fullword ascii
    $s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
    $s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
    $s5 = "Mutex object did not timeout, list not patched" fullword ascii
    $s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}