rule Suckfly_Nidiran_Gen_1 {
  meta:
    author = Spider
    comment = None
    date = 2018-01-28
    description = Detects Suckfly Nidiran Trojan
    family = 1
    hacker = None
    hash1 = ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates
    threatname = Suckfly[Nidiran]/Gen.1
    threattype = Nidiran
  strings:
    $s1 = "WriteProcessMemory fail at %d " fullword ascii
    $s2 = "CreateRemoteThread fail at %d " fullword ascii
    $s3 = "CreateRemoteThread Succ" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}