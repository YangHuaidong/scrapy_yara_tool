rule OpCloudHopper_Cloaked_PSCP {
   meta:
      description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}