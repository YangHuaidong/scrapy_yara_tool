rule PowerShell_Emp_Eval_Jul17_A2 {
  meta:
    author = Spider
    comment = None
    date = 2017-07-27
    description = Detects suspicious sample with PowerShell content 
    family = Jul17
    hacker = None
    hash1 = e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = PowerShell Empire Eval
    threatname = PowerShell[Emp]/Eval.Jul17.A2
    threattype = Emp
  strings:
    $x1 = "\\support\\Release\\ab.pdb" ascii
    $s2 = "powershell.exe" ascii fullword
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}