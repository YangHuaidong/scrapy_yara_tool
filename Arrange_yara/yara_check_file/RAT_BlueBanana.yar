rule RAT_BlueBanana
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlueBanana RAT"
		reference = "http://malwareconfig.com/stats/BlueBanana"
		maltype = "Remote Access Trojan"
		filetype = "Java"
	strings:
		$meta = "META-INF"
		$conf = "config.txt"
		$a = "a/a/a/a/f.class"
		$b = "a/a/a/a/l.class"
		$c = "a/a/a/b/q.class"
		$d = "a/a/a/b/v.class"
	condition:
		all of them
}