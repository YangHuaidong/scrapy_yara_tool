rule SUSP_Script_Obfuscation_Char_Concat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-10-04"
    description = "Detects strings found in sample from CN group repo leak in October 2018"
    family = "None"
    hacker = "None"
    hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
    judge = "black"
    reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
  condition:
    1 of them
}