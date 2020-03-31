rule PowerShell_in_Word_Doc {
  meta:
    author = Spider
    comment = None
    date = 2017-06-27
    description = Detects a powershell and bypass keyword in a Word document
    family = Doc
    hacker = None
    hash1 = 4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research - ME
    score = 50
    threatname = PowerShell[in]/Word.Doc
    threattype = in
  strings:
    $s1 = "POwErSHELl.ExE" fullword ascii nocase
    $s2 = "BYPASS" fullword ascii nocase
  condition:
    ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}