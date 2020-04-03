rule OpCloudHopper_WmiDLL_inMemory {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Malware related to Operation Cloud Hopper - Page 25"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "wmi.dll 2>&1" ascii
  condition:
    all of them
}