rule SUSP_PowerShell_Caret_Obfuscation_2 {
  meta:
    author = Spider
    comment = None
    date = 2019-07-20
    description = Detects powershell keyword obfuscated with carets
    family = Obfuscation
    hacker = None
    judge = unknown
    reference = Internal Research
    threatname = SUSP[PowerShell]/Caret.Obfuscation.2
    threattype = PowerShell
  strings:
    $r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword
    $r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword
  condition:
    1 of them
}