rule kerberoast_PY {
	meta:
		description = "Auto-generated rule - file kerberoast.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
	strings:
		$s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
		$s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
		$s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
	condition:
		2 of them
}