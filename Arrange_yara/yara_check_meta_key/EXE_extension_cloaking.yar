rule EXE_extension_cloaking {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Executable showing different extension (Windows default 'hide known extension')"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  condition:
    filename matches /\.txt\.exe$/is or	// Special file extensions
    filename matches /\.pdf\.exe$/is		// Special file extensions
}