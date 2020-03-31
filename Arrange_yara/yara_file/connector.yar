rule connector {
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"
	condition:
		all of them
}