rule EXE_cloaked_as_TXT {
	meta:
		description = "Executable with TXT extension"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
	condition:
		uint16(0) == 0x5a4d 					// Executable
		and filename matches /\.txt$/is   // TXT extension (case insensitive)
}