rule OpCloudHopper_WindowXarBot {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Malware related to Operation Cloud Hopper"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Release\\WindowXarbot.pdb" ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}