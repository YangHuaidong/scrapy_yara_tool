rule Cloaked_RAR_File {
	meta:
		description = "RAR file cloaked by a different extension"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
	condition:
		uint32be(0) == 0x52617221							// RAR File Magic Header
		and not filename matches /(rarnew.dat|\.rar)$/is	// not the .RAR extension
		and not filepath contains "Recycle" 				// not a deleted RAR file in recycler
}