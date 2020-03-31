rule Empire_lib_modules_credentials_mimikatz_pth {
  meta:
    author = Spider
    comment = None
    date = 2015-08-06
    description = Empire - a pure PowerShell post-exploitation agent - file pth.py
    family = credentials
    hacker = None
    hash = 6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/PowerShellEmpire/Empire
    score = 70
    threatname = Empire[lib]/modules.credentials.mimikatz.pth
    threattype = lib
  strings:
    $s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
    $s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii
  condition:
    filesize < 12KB and all of them
}