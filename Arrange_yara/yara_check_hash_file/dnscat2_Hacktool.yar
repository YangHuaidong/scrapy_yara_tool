rule dnscat2_Hacktool {
  meta:
    author = Spider
    comment = None
    date = 2016-05-15
    description = Detects dnscat2 - from files dnscat, dnscat2.exe
    family = None
    hacker = None
    hash1 = 8bc8d6c735937c9c040cbbdcfc15f17720a7ecef202a19a7bf43e9e1c66fe66a
    hash2 = 4a882f013419695c8c0ac41d8a0fde1cf48172a89e342c504138bc6f1d13c7c8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://downloads.skullsecurity.org/dnscat2/
    super_rule = 1
    threatname = dnscat2[Hacktool
    threattype = Hacktool.yar
  strings:
    $s1 = "--exec -e <process>     Execute the given process and link it to the stream." fullword ascii
    $s2 = "Sawlog" fullword ascii
    $s3 = "COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s" fullword ascii
    $s4 = "COMMAND_SHELL [request] :: request_id: 0x%04x :: name: %s" fullword ascii
    $s5 = "[Tunnel %d] connection to %s:%d closed by the server!" fullword ascii
  condition:
    ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 400KB and ( 2 of ($s*) ) ) or ( all of them )
}