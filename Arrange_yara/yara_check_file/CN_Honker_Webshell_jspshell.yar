rule CN_Honker_Webshell_jspshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d16af622f7688d4e0856a2678c4064d3d120e14b"
	strings:
		$s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii /* PEStudio Blacklist: strings */
		$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and all of them
}