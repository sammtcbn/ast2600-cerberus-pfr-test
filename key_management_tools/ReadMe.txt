1. The key management tool creates the key provision/cancellation/decommission image with the recovery header.
   The generated key management image is signed by root key.
2. Please configure the "cancellation_image_generator.config", "decommission_image_generator.config" and
   "key_manifest_image_generator.config" file with the valid data.
3. This tool requires the input XML file and this file has the type of the image, recovery sections details.
4. The valid values for type that can be provided in the xml are as follows,
        Key Cancellation: 4
        Decommission: 5
        Key Manifest Provisioning: 6
5.  Below is the structure of the cancellation image file.
    5.1 Key Cancellation Image structure:
        ```
        struct key_cancellation_manifest {
            struct recovery_header image_header;
            struct recovery_section image_section;
            struct key_cancellation{
                    uint32_t magic_number;   // 0x4b455943   'KEYC'
                    uint16_t key_policy;     // 0x0100 = ROT, 0x0101 = PCH, 0x0103 = BMC
                    uint8_t hash_type;       // 1: 256(default); 2: 384; 3: 512
                    uint8_t key_count;       // 8(maximum)
                    struct key_cancel_list {
                            uint8_t key_id;
                            uint8_t key_hash[64];
                    } key_cancel_list[key_count]
            }
            uint8_t signature[];              // rsa2048: 256 bytes;
            struct rsa_public_key {
                    uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
                    size_t mod_length;
                    uint32_t exponent;
            } root_pub_key;
        };
        ```

    5.2 Key Manifest Image structure:
        ```
        struct key_provision_manifest {
            struct recovery_header image_header;
            struct recovery_section image_section;
            struct key_cancellation{
                    uint32_t magic_number;   // 0x6b65796d   'keym'
                    uint8_t hash_type;       // 1: 256(default); 2: 384; 3: 512
                    uint8_t key_count;       // 8(maximum)
                    struct key_list {
                            uint8_t key_hash[64];
                    } key_list[key_count]
            }
            uint8_t signature[];              // rsa2048: 256 bytes;
            struct rsa_public_key {
                    uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
                    size_t mod_length;
                    uint32_t exponent;
            } root_pub_key;
        };
        ```

    5.3 Decommission Image structure:
        ```
        struct decommission {
            struct recovery_header image_header;
            struct recovery_section image_section;
            uint8_t signature[];              // rsa2048: 256 bytes;
            struct rsa_public_key {
                    uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
                    size_t mod_length;
                    uint32_t exponent;
            } root_pub_key;
        };
        ```

6. Sample XML
    6.1 Key Cancellation(key_cancellation.xml):
        ```
        <CancellationImage version="08.04" platform="Server-BMC" type="4">
          <CancellationSection>
              <CancellationPolicy>BMC</CancellationPolicy> <!-- BMC, PCH or ROT -->
              <HashType>SHA256</HashType>
              <Key>
                  <KeyId>0</KeyId>
                  <PublicKey>pubcsk0_2048.pem</PublicKey>
              </Key>
              <Key>
                  <KeyId>2</KeyId>
                  <PublicKey>pubcsk2_2048.pem</PublicKey>
              </Key>
          </CancellationSection>
        </CancellationImage>
        ```

    6.2 Key Manifest(key_manifest.xml):
        ```
        <KeyManifestImage version="08.04" platform="Server-BMC" type="6">
          <KeyManifestSection>
              <HashType>SHA256</HashType>
              <Key>
                  <PublicKey>pubcsk0_2048.pem</PublicKey>
              </Key>
              <Key>
                  <PublicKey>pubcsk1_2048.pem</PublicKey>
              </Key>
              <Key>
                  <PublicKey>pubcsk2_2048.pem</PublicKey>
              </Key>
          </KeyManifestSection>
        </KeyManifestImage>
        ```
    6.3 Decommission(decommission.xml):
        ```
        <DecommissionImage version="01.04.00" platform="rot" type="5">
        </DecommissionImage>
        ```

7. Sample Config
    7.1 Key Cancellation(cancellation_image_generator.config):
        ```
        Xml=key_cancellation.xml
        Output=key_cancel.signed.bin
        Key=prikey_2048.pem
        Cancel_Key=pubcsk0_2048.pem
        Cancel_Key=pubcsk1_2048.pem
        Cancel_Key=pubcsk2_2048.pem
        ```

    7.2 Key Manifest(key_manifest_image_generator.config):
        ```
        Xml=key_manifest.xml
        Output=key_provision.signed.bin
        Key=prikey_2048.pem
        Signing_Key=pubcsk0_2048.pem
        Signing_Key=pubcsk1_2048.pem
        Signing_Key=pubcsk2_2048.pem
        ```

    7.3 Decommission(decommission_image_generator.config):
        ```
        Xml=decommission.xml
        Output=decom.signed.bin
        Key=prikey_2048.pem
        ```

8. To generate the key manifest/cancellation/decommission image, please run the python script as follows,
        python3 key_management_tool.py key_manifest_image_generator.config
        python3 key_management_tool.py cancellation_image_generator.config
        python3 key_management_tool.py decommission_image_generator.config
