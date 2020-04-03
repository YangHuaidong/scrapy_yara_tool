rule OPCLEAVER_SmartCopy2
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
	strings:
		$s1 = "SmartCopy2.Properties"
		$s2 = "ZhuFrameWork"
	condition:
		all of them
}