rule CN_Honker_Webshell_Injection_Transit_jmPost {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 9KB and all of them
}