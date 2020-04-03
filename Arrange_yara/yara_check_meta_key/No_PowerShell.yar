rule No_PowerShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-05-21"
    description = "Detects an C# executable used to circumvent PowerShell detection - file nps.exe"
    family = "None"
    hacker = "None"
    hash1 = "64f811b99eb4ae038c88c67ee0dc9b150445e68a2eb35ff1a0296533ae2edd71"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Ben0xA/nps"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "nps.exe -encodedcommand {base64_encoded_command}" fullword wide
    $s2 = "c:\\Development\\ghps\\nps\\nps\\obj\\x86\\Release\\nps.pdb" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($s*) ) ) or ( all of them )
}