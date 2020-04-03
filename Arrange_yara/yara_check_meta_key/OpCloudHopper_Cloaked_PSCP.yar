rule OpCloudHopper_Cloaked_PSCP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "AES-256 SDCTR" ascii
    $s2 = "direct-tcpip" ascii
  condition:
    all of them and filename == "rundll32.exe"
}