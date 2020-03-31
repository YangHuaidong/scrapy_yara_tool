rule WebShell_Generic_PHP_1 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - from files Dive Shell 1.0
    family = 1
    hacker = None
    hash0 = 3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b
    hash1 = 2558e728184b8efcdb57cfab918d95b06d45de04
    hash2 = 203a8021192531d454efbc98a3bbb8cabe09c85c
    hash3 = b79709eb7801a28d02919c41cc75ac695884db27
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    super_rule = 1
    threatname = WebShell[Generic]/PHP.1
    threattype = Generic
  strings:
    $s1 = "$token = substr($_REQUEST['command'], 0, $length);" fullword
    $s4 = "var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword
    $s7 = "$_SESSION['output'] .= htmlspecialchars(fgets($io[1])," fullword
    $s9 = "document.shell.command.value = command_hist[current_line];" fullword
    $s16 = "$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $"
    $s19 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {" fullword
    $s20 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword
  condition:
    5 of them
}