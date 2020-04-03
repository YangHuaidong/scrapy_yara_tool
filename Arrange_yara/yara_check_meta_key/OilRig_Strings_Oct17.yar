rule OilRig_Strings_Oct17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-18"
    description = "Detects strings from OilRig malware and malicious scripts"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
    $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
    $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" fullword ascii
    $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" fullword ascii
    $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
  condition:
    filesize < 800KB and 1 of them
}