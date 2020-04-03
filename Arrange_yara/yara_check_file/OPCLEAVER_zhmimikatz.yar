rule OPCLEAVER_zhmimikatz
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
	strings:
		$s1 = "MimikatzRunner"
		$s2 = "zhmimikatz"
	condition:
		all of them
}