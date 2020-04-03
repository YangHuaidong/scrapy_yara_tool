rule EquationGroup_wrap_telnet {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
    family = "None"
    hacker = "None"
    hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
    $s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
    $s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 4KB and 1 of them )
}