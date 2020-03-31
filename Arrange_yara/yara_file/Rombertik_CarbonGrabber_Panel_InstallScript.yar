rule Rombertik_CarbonGrabber_Panel_InstallScript {
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
	strings:
		$s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
		$s3 = "`post` text NOT NULL," fullword ascii
		$s4 = "`host` text NOT NULL," fullword ascii
		$s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
		$s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
		$s9 = "$db->exec($insert);" fullword ascii
		$s10 = "`browser` text NOT NULL," fullword ascii
		$s13 = "`ip` text NOT NULL," fullword ascii
	condition:
		filesize < 3KB and all of them
}