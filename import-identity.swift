import Foundation
import Security
import CryptoKit

enum Failure: Error { case refused }
func require(_ condition: Bool) throws {
    if !condition { throw Failure.refused }
}

func importIdentity() throws {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    try require(input.count < 65536)
    guard let values = try JSONSerialization.jsonObject(with: input) as? [String: String],
          let path = values["path"], let encoded = values["archive"],
          let password = values["password"], let archive = Data(base64Encoded: encoded)
    else { throw Failure.refused }
    try require(path.hasPrefix("/") && !FileManager.default.fileExists(atPath: path))
    try require(ProcessInfo.processInfo.environment["RUNNER_ENVIRONMENT"] == "github-hosted")
    try require(SecKeychainSetUserInteractionAllowed(false) == errSecSuccess)
    var originalList: CFArray?
    var originalDefault: SecKeychain?
    try require(SecKeychainCopySearchList(&originalList) == errSecSuccess)
    try require(SecKeychainCopyDefault(&originalDefault) == errSecSuccess)
    guard let originalList, let originalDefault else { throw Failure.refused }
    var random = [UInt8](repeating: 0, count: 48)
    try require(SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess)
    var keychain: SecKeychain?
    let created = random.withUnsafeBytes {
        SecKeychainCreate(path, UInt32($0.count), $0.baseAddress, false, nil, &keychain)
    }
    var success = false
    defer {
        if !success {
            SecKeychainSetSearchList(originalList)
            if let keychain { SecKeychainDelete(keychain) }
        }
    }
    // Creating a legacy Keychain may add it to the search list. Restore both
    // ambient selectors before checking creation or importing any secret key.
    let listRestored = SecKeychainSetSearchList(originalList)
    let defaultRestored = SecKeychainSetDefault(originalDefault)
    try require(listRestored == errSecSuccess && defaultRestored == errSecSuccess)
    try require(created == errSecSuccess)
    guard let keychain else { throw Failure.refused }
    let unlocked = random.withUnsafeBytes {
        SecKeychainUnlock(keychain, UInt32($0.count), $0.baseAddress, true)
    }
    try require(unlocked == errSecSuccess)
    var trusted: SecTrustedApplication?
    try require(SecTrustedApplicationCreateFromPath("/usr/bin/codesign", &trusted) == errSecSuccess)
    guard let trusted else { throw Failure.refused }
    var access: SecAccess?
    try require(SecAccessCreate("Kitrove isolated signing" as CFString,
        [trusted] as CFArray, &access) == errSecSuccess)
    guard let access else { throw Failure.refused }
    let wrappingPassword = password as CFString
    var parameters = SecItemImportExportKeyParameters()
    parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
    parameters.passphrase = Unmanaged.passUnretained(wrappingPassword)
    parameters.accessRef = Unmanaged.passUnretained(access)
    var format = SecExternalFormat.formatPKCS12
    var type = SecExternalItemType.itemTypeAggregate
    var imported: CFArray?
    let status = withExtendedLifetime((wrappingPassword, access)) {
        SecItemImport(archive as CFData, nil, &format, &type, [], &parameters, keychain, &imported)
    }
    try require(status == errSecSuccess)
    let items = imported as? [AnyObject] ?? []
    let identities = items.filter { CFGetTypeID($0) == SecIdentityGetTypeID() }
    try require(identities.count == 1)
    let identity = identities[0] as! SecIdentity
    var certificate: SecCertificate?
    try require(SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess)
    guard let certificate else { throw Failure.refused }
    let fingerprint = Insecure.SHA1.hash(data: SecCertificateCopyData(certificate) as Data)
        .map { String(format: "%02X", $0) }.joined()
    try require(fingerprint == "D9A906454D05C808AA070F9BC91F1A29BF0F6CC6")
    // codesign requires search-list membership even with explicit --keychain.
    // The orchestrator snapshots the original list before import and restores it
    // in finally. Keep the default Keychain unchanged and append only this store.
    let signingList = (originalList as! [SecKeychain]) + [keychain]
    try require(SecKeychainSetSearchList(signingList as CFArray) == errSecSuccess)
    success = true
    print("Approved identity imported into the isolated Keychain.")
}

do { try importIdentity() }
catch {
    // Never emit credential-bearing input or native provider diagnostics.
    FileHandle.standardError.write(Data("Isolated Keychain import failed.\n".utf8))
    exit(1)
}
