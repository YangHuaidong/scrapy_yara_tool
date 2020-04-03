rule PowerShell_Emp_Eval_Jul17_A1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-27"
    description = "Detects suspicious sample with PowerShell content "
    family = "None"
    hacker = "None"
    hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "PowerShell Empire Eval"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "powershell" wide
    $s2 = "pshcmd" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}