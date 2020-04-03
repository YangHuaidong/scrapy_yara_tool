rule EQGRP_RC5_RC6_Opcode {
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		date = "2016-08-17"
	strings:
		/*
			mov     esi, [ecx+edx*4-4]
			sub     esi, 61C88647h
			mov     [ecx+edx*4], esi
			inc     edx
			cmp     edx, 2Bh
		*/
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
	condition:
		1 of them
}