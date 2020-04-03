rule SqlDbx_zhs {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
    family = "None"
    hacker = "None"
    hash = "e34228345498a48d7f529dbdffcd919da2dea414"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
    $s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
    $s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
    $s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
    $s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
    $s12 = "mailto:support@sqldbx.com" fullword ascii
    $s15 = "S.last_login_time \"Last Login\", " fullword ascii
  condition:
    uint16(0) == 0x5a4d and 4 of them
}