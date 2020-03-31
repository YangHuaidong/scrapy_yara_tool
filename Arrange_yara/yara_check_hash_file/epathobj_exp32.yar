rule epathobj_exp32 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file epathobj_exp32.exe
    family = None
    hacker = None
    hash = ed86ff44bddcfdd630ade8ced39b4559316195ba
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = epathobj[exp32
    threattype = exp32.yar
  strings:
    $s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
    $s1 = "Exploit ok run command" fullword ascii
    $s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
    $s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
    $s4 = "Mutex object did not timeout, list not patched" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 270KB and all of them
}