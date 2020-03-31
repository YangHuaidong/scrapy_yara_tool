rule HYTop_AppPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
	condition:
		all of them
}