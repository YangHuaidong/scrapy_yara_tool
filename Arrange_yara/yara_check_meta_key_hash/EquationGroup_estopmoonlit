rule EquationGroup_estopmoonlit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file estopmoonlit"
    family = "None"
    hacker = "None"
    hash1 = "707ecc234ed07c16119644742ebf563b319b515bf57fd43b669d3791a1c5e220"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[+] shellcode prepared, re-executing" fullword ascii
    $x2 = "[-] kernel not vulnerable: prctl" fullword ascii
    $x3 = "[-] shell failed" fullword ascii
    $x4 = "[!] selinux apparently enforcing.  Continue [y|n]? " fullword ascii
  condition:
    filesize < 250KB and 1 of them
}