rule OpenGuard_Inert_Test_Marker : test {
    meta:
        description = "OpenGuard inert YARA-X integration test marker"
        severity = "malicious"
    strings:
        $marker = "OPENGUARD_INERT_YARA_TEST_MARKER_2026" ascii
    condition:
        $marker
}

rule OpenGuard_Suspicious_PowerShell_Download : script {
    meta:
        description = "PowerShell combines dynamic execution with remote content retrieval"
        severity = "suspicious"
    strings:
        $exec = /(?:invoke-expression|iex)/ nocase ascii
        $download = /(?:downloadstring|invoke-webrequest|start-bitstransfer)/ nocase ascii
    condition:
        filesize < 4MB and all of them
}

rule OpenGuard_Suspicious_Process_Injection_References : executable {
    meta:
        description = "File contains a cluster of process-injection API names"
        severity = "suspicious"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
    condition:
        filesize < 64MB and 2 of them
}
