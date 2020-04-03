rule OpCloudHopper_WindowXarBot {
   meta:
      description = "Malware related to Operation Cloud Hopper"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
   strings:
      $s1 = "\\Release\\WindowXarbot.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}