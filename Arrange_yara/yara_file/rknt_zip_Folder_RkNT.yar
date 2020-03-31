rule rknt_zip_Folder_RkNT {
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "5f97386dfde148942b7584aeb6512b85"
	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"
	condition:
		all of them
}