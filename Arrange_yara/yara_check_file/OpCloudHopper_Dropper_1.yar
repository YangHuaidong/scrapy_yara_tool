rule OpCloudHopper_Dropper_1 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "411571368804578826b8f24f323617f51b068809b1c769291b21125860dc3f4e"
   strings:
      $s1 = "{\\version2}{\\edmins0}{\\nofpages1}{\\nofwords11}{\\nofchars69}{\\*\\company google}{\\nofcharsws79}{\\vern24611}{\\*\\password" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and all of them )
}