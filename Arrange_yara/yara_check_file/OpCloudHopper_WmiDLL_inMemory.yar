rule OpCloudHopper_WmiDLL_inMemory {
   meta:
      description = "Malware related to Operation Cloud Hopper - Page 25"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
   strings:
      $s1 = "wmi.dll 2>&1" ascii
   condition:
      all of them
}