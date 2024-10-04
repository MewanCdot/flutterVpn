import Foundation
import Security

class CertificateManager {
    
    static let shared = CertificateManager()

    private init() {}

    // Pinned certificate PEM
    private let pinnedCertificatePEM: String = """
    -----BEGIN CERTIFICATE-----
    MIIFQjCCAyqgAwIBAgIIWdKa7ulL9r8wDQYJKoZIhvcNAQEMBQAwPzELMAkGA1UE
    BhMCQ0gxEzARBgNVBAoTCnN0cm9uZ1N3YW4xGzAZBgNVBAMTEnN0cm9uZ1N3YW4g
    Um9vdCBDQTAeFw0yNDA5MjYwNDQxMDhaFw0zNDA5MjYwNDQxMDhaMD8xCzAJBgNV
    BAYTAkNIMRMwEQYDVQQKEwpzdHJvbmdTd2FuMRswGQYDVQQDExJzdHJvbmdTd2Fu
    IFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCyki6Rzc3Q
    gfMFDAd8Yg7F+TpTlQbXSovLwLkmqaQTQkC9yUVC6Y0li39cLhzzKEtizU4Trfxw
    lDmOnyA9o/8kQ4Ndbu6CE/ennU+e8/GvU3Kycvuf8XGWRcX88f9w+MEu+Zaohk1E
    5lUkkwQuDC5+LqOcwBaveatLpjjp17CKXyL+C5OeCEG3V7rCljClXFoVD3YAsiq+
    1+16oNRagGs5kk2+bpZMQ39ooUZDexVXSzPbWjwQrap5XxId+zedusjypvnhqt/S
    VPvS9j4mjZvrUHyTig5OPEErbGWFchwBxZRl7r+g/+fdTUEwOuOEVEdnC54f/Hlu
    /Vg3JptbXU/fBNFf4px0i6IWzHM+yssnR2stsWscBW3h6/Cs9IHcZ/Z/UqYg93N9
    BUpChMwL7qXAlzyemV9HGyL+QGgUEcn+DjIanjql9a2PmNakIINEvb0P8JMu9kme
    hlZapa/2lD72MW2MzWX0Q2OdXv+VztUdoc95A8vJ+Nhrhlfe/f1OnTT2kHIghIz7
    mA4NIdEq6rEgwxwao/uQpY584EGY+Ld/yxY3zvAjtdI9pb7x4oa+A96nUcncUVqP
    ay+vuveP6nYc8FDNF1nLq8Uj9plnwgMwOK1WRBPD335lS0L/rQ0ugP9RMmY3w/or
    GIBlJaiybPSS6MrZklS9aT+OVsl1lBWXGwIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
    AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUzQGlK3CDi6DIuKhjD0coeV07
    1QUwDQYJKoZIhvcNAQEMBQADggIBACnzWNq0/dM13NRTUl9AtO0KwRQUx9E+CX7O
    irEKMqFMDYmeYzxbUStthpeO7wyoGSUNCXa3hpGWQkD6p0UJBbtyLDs9I2+fJ9od
    MJH/xhRlvQ0E+KxWTt/5a9rY6PR56b2feJ/6qjemAEkBfgIHBRNQZsV6CeqtSbx8
    x/WP1gGFscK9v09JwhpW+8L0aCH0K4rRG73bjxYsYNj8dPvke+vBswGuZUPbNKES
    OmATnF92LfNScZIsu9M/ASr+I87f5EX7D0v3O3eer5KAbvGw33bxJw66GjLEdEV/
    7uHIgtfNK88ZJIjpenX/y8mxuL/PKrFkEXO8xeMI7G6oaaadP4DfDqCOWSnl1/Zl
    7U0N91Pvwa2DtikBERTgbUYl1bcV5MA2djc3/3Ent6eJ6DBeiepzOT2Nr1f4KcmB
    xSuk4pofFFArDxX2RVLDDkl+mIsObQOVKeMFkkGb+mkHcM5fmj5SAWd/XFLncM4R
    NbN6ckZRHh4VaP03sCfqh3SE/k2/dnfofe4MM/tgF5g8ofZYw66JPp27jfczyAyz
    26ilNoDfWUydczUeIe7bah1k7wjIthE9O1m86QMyq0semgfCOLcOHz7CMWn2RGDJ
    WqwhwdoDGnUnCXfy2FLT67nObb7yFFfbt4Rg+YvKxMV5m1Aw5xOi591L5vcm0W0o
    FFD9O4VR
    -----END CERTIFICATE-----
    """

    func getTrustedCertificates() -> [Data]? {
        var certificates = [Data]()

        // Add pinned certificate
        if let pinnedCert = loadPinnedCertificate() {
            certificates.append(pinnedCert)
        } else {
            print("Error adding pinned certificate")
            return nil
        }

        // Retrieve system-trusted certificates from the Keychain
        let keychainCerts = retrieveCertificatesFromKeychain()
        certificates.append(contentsOf: keychainCerts)
        
        // Return all certificates
        return certificates
    }

    private func loadPinnedCertificate() -> Data? {
        let cleanedPEM = pinnedCertificatePEM
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
        
        guard let certData = Data(base64Encoded: cleanedPEM) else {
            return nil
        }
        return certData
    }

    private func retrieveCertificatesFromKeychain() -> [Data] {
        var certificates = [Data]()
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let certDataArray = result as? [Data] {
            certificates.append(contentsOf: certDataArray)
        } else {
            print("Error retrieving certificates from Keychain: \(status)")
        }
        
        return certificates
    }
}
