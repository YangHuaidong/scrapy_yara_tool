rule EquationGroup_telex {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
    family = "None"
    hacker = "None"
    hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
    $x2 = "target is not vulnerable. exiting" fullword ascii
    $s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
    $s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}