rule APT_Cloaked_PsExec {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014-07-18"
    description = "Looks like a cloaked PsExec. May be APT group activity."
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "psexesvc.exe" wide fullword
    $s1 = "Sysinternals PsExec" wide fullword
  condition:
    uint16(0) == 0x5a4d and $s0 and $s1
    and not filename matches /(psexec.exe|PSEXESVC.EXE|PsExec64.exe)$/is
    and not filepath matches /RECYCLE.BIN\\S-1/
}