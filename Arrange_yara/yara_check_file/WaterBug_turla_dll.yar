rule WaterBug_turla_dll {
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla DLL"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
	condition:
		pe.exports("ee") and $a
}