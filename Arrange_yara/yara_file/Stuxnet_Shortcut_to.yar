rule Stuxnet_Shortcut_to {
	meta:
		description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"
	strings:
		$x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide
	condition:
		uint16(0) == 0x004c and filesize < 10KB and $x1
}