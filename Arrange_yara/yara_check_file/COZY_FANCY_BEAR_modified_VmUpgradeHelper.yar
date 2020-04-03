rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
	meta:
		description = "Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
	strings:
		$s1 = "VMware, Inc." wide fullword
		$s2 = "Virtual hardware upgrade helper service" fullword wide
		$s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		filename == "VmUpgradeHelper.exe" and
		not all of ($s*)
}