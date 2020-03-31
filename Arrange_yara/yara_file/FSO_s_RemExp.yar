rule FSO_s_RemExp {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
	condition:
		all of them
}