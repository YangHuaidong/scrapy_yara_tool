rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
  meta:
    author = Spider
    comment = None
    date = 2016-06-14
    description = Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report
    family = modified
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/
    threatname = COZY[FANCY]/BEAR.modified.VmUpgradeHelper
    threattype = FANCY
  strings:
    $s1 = "VMware, Inc." wide fullword
    $s2 = "Virtual hardware upgrade helper service" fullword wide
    $s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
  condition:
    uint16(0) == 0x5a4d and
    filename == "VmUpgradeHelper.exe" and
    not all of ($s*)
}