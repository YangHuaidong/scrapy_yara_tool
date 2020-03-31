rule sig_2005Gray {
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"
	strings:
		$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
		$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
		$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
	condition:
		all of them
}