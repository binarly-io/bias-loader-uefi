## Format

```sh

struct EFI_SIGNATURE_DATABASE {
  struct EFI_SIGNATURE_LIST {                            |
    EFI_GUID SignatureType;                              |
    UINT32   SignatureListSize; -------------------------+
    UINT32   SignatureHeaderSize;                        |
    UINT32   SignatureSize; ---------------------------+ |
    UINT8    SignatureHeader[SignatureHeaderSize];     | |
                                                       v |
    struct EFI_SIGNATURE_DATA {                        | |
      EFI_GUID SignatureOwner;                         | |
      UINT8    SignatureData[1] = {                    | |
        X.509 payload                                  | |
      }                                                | |
    } Signatures[];                                      |
  } SigLists[];
};

```
