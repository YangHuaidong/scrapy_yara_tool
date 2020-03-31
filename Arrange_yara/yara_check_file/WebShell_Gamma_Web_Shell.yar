rule WebShell_Gamma_Web_Shell {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Gamma Web Shell.php
    family = Shell
    hacker = None
    hash = 7ef773df7a2f221468cc8f7683e1ace6b1e8139a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Gamma]/Web.Shell
    threattype = Gamma
  strings:
    $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
    $s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
    $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
    $s20 = "my $command = $self->query('command');" fullword
  condition:
    2 of them
}