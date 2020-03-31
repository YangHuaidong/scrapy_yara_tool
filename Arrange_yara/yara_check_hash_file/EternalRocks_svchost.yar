rule EternalRocks_svchost {
  meta:
    author = Spider
    comment = None
    date = 2017-05-18
    description = Detects EternalRocks Malware - file taskhost.exe
    family = None
    hacker = None
    hash1 = 589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/stamparm/status/864865144748298242
    threatname = EternalRocks[svchost
    threattype = svchost.yar
  strings:
    $s1 = "WczTkaJphruMyBOQmGuNRtSNTLEs" fullword ascii
    $s2 = "svchost.taskhost.exe" fullword ascii
    $s3 = "ConfuserEx v" ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and 2 of them )
}