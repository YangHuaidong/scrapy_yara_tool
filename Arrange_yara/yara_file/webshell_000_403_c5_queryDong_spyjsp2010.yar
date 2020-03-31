rule webshell_000_403_c5_queryDong_spyjsp2010 {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
	strings:
		$s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
		$s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
		$s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
		$s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
	condition:
		2 of them
}