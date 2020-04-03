rule Suckfly_Nidiran_Gen_1 {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28"
      hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
   strings:
      $s1 = "WriteProcessMemory fail at %d " fullword ascii
      $s2 = "CreateRemoteThread fail at %d " fullword ascii
      $s3 = "CreateRemoteThread Succ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}