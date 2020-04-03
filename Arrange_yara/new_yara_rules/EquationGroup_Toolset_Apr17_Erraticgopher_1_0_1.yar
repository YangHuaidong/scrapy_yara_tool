rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[-] Error appending shellcode buffer" fullword ascii
    $x2 = "[-] Shellcode is too big" fullword ascii
    $x3 = "[+] Exploit Payload Sent!" fullword ascii
    $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}