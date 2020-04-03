rule apt_RU_MoonlightMaze_encrypted_keylog {
meta:
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze encrypted keylogger logs"
strings:
	$a1={47 01 22 2A 6D 3E 39 2C}
condition:
	uint32(0) == 0x2a220147 and ($a1 at 0)
}