rule EquationGroup_Toolset_Apr17_Erraticgophertouch_1_0_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
    $x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
    $x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}