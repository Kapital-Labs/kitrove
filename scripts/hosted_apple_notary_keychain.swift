import Foundation
import Security

enum Failure: Error { case refused }
func require(_ condition: Bool) throws {
    if !condition { throw Failure.refused }
}

func createEmptyKeychain() throws {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    try require(input.count < 4096)
    guard let values = try JSONSerialization.jsonObject(with: input) as? [String: String],
          Set(values.keys) == Set(["path"]), let path = values["path"]
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
            SecKeychainSetDefault(originalDefault)
            if let keychain { SecKeychainDelete(keychain) }
        }
    }
    let listRestored = SecKeychainSetSearchList(originalList)
    let defaultRestored = SecKeychainSetDefault(originalDefault)
    try require(listRestored == errSecSuccess && defaultRestored == errSecSuccess)
    try require(created == errSecSuccess)
    guard let keychain else { throw Failure.refused }
    let unlocked = random.withUnsafeBytes {
        SecKeychainUnlock(keychain, UInt32($0.count), $0.baseAddress, true)
    }
    try require(unlocked == errSecSuccess)
    // Match production's isolated search-list membership, without importing a key.
    let isolatedList = (originalList as! [SecKeychain]) + [keychain]
    try require(SecKeychainSetSearchList(isolatedList as CFArray) == errSecSuccess)
    success = true
    print("Empty isolated notarization Keychain created.")
}

do { try createEmptyKeychain() }
catch {
    FileHandle.standardError.write(Data("Empty notarization Keychain creation failed.\n".utf8))
    exit(1)
}
