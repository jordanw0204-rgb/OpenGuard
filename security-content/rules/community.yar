rule OpenGuard_Community_Inert_Test_Marker : test {
    meta:
        description = "OpenGuard signed community-content integration marker"
        severity = "malicious"
    strings:
        $marker = "OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026" ascii
    condition:
        $marker
}
