rule FourElementSword_ResN32DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-18"
    description = "Detects FourElementSword Malware - file bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
    family = "None"
    hacker = "None"
    hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Release\\BypassUAC.pdb" ascii
    $s2 = "\\ResN32.dll" fullword wide
    $s3 = "Eupdate" fullword wide
  condition:
    all of them
}