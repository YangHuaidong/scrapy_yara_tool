rule EXE_cloaked_as_TXT {
  meta:
    author = Spider
    comment = None
    date = None
    description = Executable with TXT extension
    family = TXT
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = EXE[cloaked]/as.TXT
    threattype = cloaked
  condition:
    uint16(0) == 0x5a4d 					// Executable
    and filename matches /\.txt$/is   // TXT extension (case insensitive)
}