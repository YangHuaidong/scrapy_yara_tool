rule RAT_BlackShades
{
	meta:
		author = "Brian Wallace (@botnet_hunter)"
		date = "01.04.2014"
		description = "Detects BlackShades RAT"
		reference = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		family = "blackshades"
	strings:
		$string1 = "bss_server"
		$string2 = "txtChat"
		$string3 = "UDPFlood"
	condition:
		all of them
}