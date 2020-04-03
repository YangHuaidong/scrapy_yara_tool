rule apt_RU_MoonlightMaze_de_tool {
meta:
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
	hash = "4bc7ed168fb78f0dc688ee2be20c9703"
	hash = "8b56e8552a74133da4bc5939b5f74243"
strings:
	$a1="Vnuk: %d" ascii fullword
	$a2="Syn: %d" ascii fullword
	$a3={25 73 0A 25 73 0A 25 73 0A 25 73 0A}
condition:
	((2 of ($a*)))
}