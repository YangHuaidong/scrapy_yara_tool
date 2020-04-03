rule CN_Honker_Webshell_ASPX_aspx {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8378619b2a7d446477946eabaa1e6744dec651c1"
	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii /* PEStudio Blacklist: strings */
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii /* PEStudio Blacklist: strings */
		$s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii /* PEStudio Blacklist: strings */
		$s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 353KB and 2 of them
}