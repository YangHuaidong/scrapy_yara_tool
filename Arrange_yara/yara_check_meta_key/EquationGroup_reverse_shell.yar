rule EquationGroup_reverse_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
    family = "None"
    hacker = "None"
    hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "sh >/dev/tcp/" ascii
    $s2 = " <&1 2>&1" fullword ascii
  condition:
    ( filesize < 1KB and all of them )
}