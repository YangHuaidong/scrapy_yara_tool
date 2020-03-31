rule shelltools_g0t_root_xwhois {
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"
	condition:
		all of them
}