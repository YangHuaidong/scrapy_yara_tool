rule EQGRP_tunnel_state_reader {
	meta:
		description = "EQGRP Toolset Firewall - file tunnel_state_reader"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"
	strings:
		$s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
		$s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
	condition:
		1 of them
}