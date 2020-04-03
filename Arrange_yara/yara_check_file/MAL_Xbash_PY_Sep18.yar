rule MAL_Xbash_PY_Sep18 {
   meta:
      description = "Detects Xbash malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      date = "2018-09-18"
      hash1 = "7a18c7bdf0c504832c8552766dcfe0ba33dd5493daa3d9dbe9c985c1ce36e5aa"
   strings:
      $s1 = { 73 58 62 61 73 68 00 00 00 00 00 00 00 00 } /* sXbash\x00\x00\x00\x00\x00\x00 */
   condition:
      uint16(0) == 0x457f and filesize < 10000KB and 1 of them
}