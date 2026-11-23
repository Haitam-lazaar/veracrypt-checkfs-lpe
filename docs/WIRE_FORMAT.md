# VeraCrypt IPC Wire Format (CheckFilesystemRequest)

Reference for the `CheckFilesystemRequest` IPC packet structure, derived from
the included `poc_checkfs_inject.c` and VeraCrypt serialization code. It describes
the original little-endian Linux protocol used during reproduction. Field names
are narrow strings; wide-string values contain native four-byte characters.
Scalar sizes, lengths, and scalar values use big-endian encoding.

---

## 1. `CheckFilesystemRequest` Full Layout

```
[CheckFilesystemRequest packet]:
  [string "SerializableName"]       = [string "CheckFilesystemRequest"]
  [string "AdminPassword"]          = [string ""]
  [string "ApplicationExecutablePath"] = [wstring L""]
  [string "ElevateUserPrivileges"]  = [bool true]
  [string "FastElevation"]          = [bool false]
  [string "UserEnvPATH"]            = [string ""]
  [string "UseDummySudoPassword"]   = [bool false]
  [string "AllowInsecureMount"]     = [bool false]

  [serialized VolumeInfo object]:
    [string "SerializableName"] = [string "VolumeInfo"]
    [string "ProgramVersion"]   = [uint32 0x0126]
    [string "AuxMountPoint"]   = [wstring L""]
    [string "EncryptionAlgorithmBlockSize"]    = [uint32 0]
    [string "EncryptionAlgorithmKeySize"]      = [uint32 0]
    [string "EncryptionAlgorithmMinBlockSize"] = [uint32 0]
    [string "EncryptionAlgorithmName"] = [wstring L""]
    [string "EncryptionModeName"]      = [wstring L""]
    [string "HeaderCreationTime"]        = [uint64 0]
    [string "HiddenVolumeProtectionTriggered"] = [bool false]
    [string "LoopDevice"]               = [wstring L""]
    [string "MinRequiredProgramVersion"]  = [uint32 0]
    [string "MountPoint"]               = [wstring L""]
    [string "Path"]                     = [wstring L""]
    [string "Pkcs5IterationCount"]       = [uint32 0]
    [string "Pkcs5PrfName"]             = [wstring L""]
    [string "Protection"]                = [int32 0]
    [string "SerialInstanceNumber"]      = [uint64 0]
    [string "Size"]                      = [uint64 0]
    [string "SlotNumber"]                = [uint32 0]
    [string "SystemEncryption"]          = [bool false]
    [string "TopWriteOffset"]            = [uint64 0]
    [string "TotalDataRead"]             = [uint64 0]
    [string "TotalDataWritten"]          = [uint64 0]
    [string "Type"]                      = [int32 0]
    [string "VirtualDevice"]            = [wstring L"INJECTION_PAYLOAD"]
    [string "VolumeCreationTime"]        = [uint64 0]
    [string "Pim"]                       = [int32 0]
    [string "MasterKeyVulnerable"]       = [bool false]

  [string "Repair"] = [bool false]
```

---

## 2. C Encoding Helper

See [poc_checkfs_inject.c](../exploit/poc_checkfs_inject.c) for the complete implementation. Key serialization
constants:

| Value | Type | Wire size (bytes) | Encoding |
|---|---|---|---|
| Empty string | string | 17 | `[BE64 8][BE64 1][00]` |
| Empty wide string | wstring | 20 | `[BE64 8][BE64 4][00 00 00 00]` |
| Boolean | uint8 | 9 | `[BE64 1][00 or 01]` |
| Zero uint32 | uint32 | 12 | `[BE64 4][00 00 00 00]` |
| Zero uint64 | uint64 | 16 | `[BE64 8][eight zero bytes]` |
| Zero int32 | int32 | 12 | Same representation as zero uint32 |
| Field name | string | Variable | A narrow string before each value |

## Session framing

A new elevated service waits for the sync bytes `00 11 22` before entering its
request loop. The included live-session PoC targets a service that already
completed that handshake and sends only the serialized request, without a sync
prefix or an `ExitRequest`.

## Later validation

The supplied packet has an empty `AuxMountPoint`. The Linux validation included
in 1.26.30 and 1.26.31 rejects that value before reaching shell command
construction. Supplying a real mount point also causes the checker to resolve
and verify the volume's device rather than use the request's `VirtualDevice`.
See [the mitigation analysis](VULNERABILITY.md#subsequent-linux-mitigation).
