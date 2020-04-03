rule EquationGroup_porkclient {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
    family = "None"
    hacker = "None"
    hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-c COMMAND: shell command string" fullword ascii
    $s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
    $s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}