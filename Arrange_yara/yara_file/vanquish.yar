rule vanquish {
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "684450adde37a93e8bb362994efc898c"
	strings:
		$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
		$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
		$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
	condition:
		all of them
}