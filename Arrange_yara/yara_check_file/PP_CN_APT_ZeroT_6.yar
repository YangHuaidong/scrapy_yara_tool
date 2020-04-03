rule PP_CN_APT_ZeroT_6 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a16078c6d09fcfc9d6ff7a91e39e6d72e2d6d6ab6080930e1e2169ec002b37d3"
   strings:
      $s1 = "jGetgQ|0h9=" fullword ascii
      $s2 = "\\sfxrar32\\Release\\sfxrar.pdb"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}