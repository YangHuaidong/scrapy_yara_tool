rule adjustcr {
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}