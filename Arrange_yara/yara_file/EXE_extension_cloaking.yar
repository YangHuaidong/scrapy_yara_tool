rule EXE_extension_cloaking {
	meta:
		description = "Executable showing different extension (Windows default 'hide known extension')"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
	condition:
		filename matches /\.txt\.exe$/is or	// Special file extensions
		filename matches /\.pdf\.exe$/is		// Special file extensions
}