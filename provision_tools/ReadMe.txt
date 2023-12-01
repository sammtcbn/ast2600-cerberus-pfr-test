Provision Root Key

Image Length - 2 bytes - 0x00 - Length of the whole imgae
Image Type  - 2 bytes - 0x02 - value(0x02)
Magic Num - 4 bytes - 0x04 - 0x8A147c29
Manifest Length - 2 bytes - 0x08 - Length of the manifest having
                    1. BmcActiveOffsets
                    2. BmcActiveSize
                    3. BmcRecoveryOffset
                    4. BmcRecoverySize
                    5. BmcStagingOffset
                    6. BmcStagingSize
                    7. PchActiveOffsets
                    8. PchActiveSize
                    9. PchRecoveryOffset
                    10. PchRecoverySize
                    11. PchStagingOffset
                    12. PchStagingSize
                    13. Public key of the root key
Flag - 4 bytes - 0x0A - Mentions whether it is for "Provisioning Root Key" or "Provisioning OTP key"
Reserved - 2 bytes - 0x0E
BmcActiveOffsets - 4 bytes - 0x10
BmcActiveSize  - 4 bytes - 0x14
BmcRecoveryOffset  - 4 bytes - 0x18
BmcRecoverySize  - 4 bytes - 0x1C
BmcStagingOffset  - 4 bytes - 0x20
BmcStagingSize  - 4 bytes - 0x24
PchActiveOffsets  - 4 bytes - 0x28
PchActiveSize  - 4 bytes - 0x2c
PchRecoveryOffset  - 4 bytes - 0x30
PchRecoverySize  - 4 bytes - 0x34
PchStagingOffset  - 4 bytes- 0x38
PchStagingSize  - 4 bytes - 0x3c
Public key of the root key - 520 bytes - 0x40
    rsa public key structure:
    struct rsa_public_key {
        uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
        size_t mod_length;
        uint32_t exponent;
    } root_pub_key;
Signature that signs the above data - 256 bytes - 0x248


Provision OTP Key (Not support yet)

Image Length - 2 bytes - 0x00 - Length of the whole imgae
Image Type  - 2 bytes - 0x02 - value(0x02)
Magic Num - 4 bytes - 0x04 - 0x8A147c29
Manifest Length - 2 bytes - 0x08 - Length of the manifest having
                    1. BmcActiveOffsets
                    2. BmcActiveSize
                    3. BmcRecoveryOffset
                    4. BmcRecoverySize
                    5. BmcStagingOffset
                    6. BmcStagingSize
                    7. PchActiveOffsets
                    8. PchActiveSize
                    9. PchRecoveryOffset
                    10. PchRecoverySize
                    11. PchStagingOffset
                    12. PchStagingSize
                    13. Public key of the root key
                    14. Public key of the OTP key
Flag - 4 bytes - 0x0A - Mentions whether it is for "Provisioning Root Key" or "Provisioning OTP key"
Reserved - 2 bytes - 0x0E
BmcActiveOffsets - 4 bytes - 0x10
BmcActiveSize  - 4 bytes - 0x14
BmcRecoveryOffset  - 4 bytes - 0x18
BmcRecoverySize  - 4 bytes - 0x1C
BmcStagingOffset  - 4 bytes - 0x20
BmcStagingSize  - 4 bytes - 0x24
PchActiveOffsets  - 4 bytes - 0x28
PchActiveSize  - 4 bytes - 0x2C
PchRecoveryOffset  - 4 bytes - 0x30
PchRecoverySize  - 4 bytes - 0x34
PchStagingOffset  - 4 bytes- 0x38
PchStagingSize  - 4 bytes - 0x3C
Public key of the root key - 520 bytes - 0x40
Public key of the OTP key - 520 bytes - 0x248
Signature that signs the above data - 256 bytes - 0x450
Zephyr Image Length - 4 bytes
Zephyr binary data


Steps to run the Provisioning Tool

Requires Python3

1. Please provide the valid inputs in the confirguration file - provisioning_image_generator.ini
    [input Section]
    input_json = <The input json file name that contains the provisioning data>
    key_type = <The key type used to sign the image>
    key_size = <The size of key>
    output_file = <The Output Provisioning file name>
2. Please provide the valid inputs in the JSON File
    {
    "Flag": "0x01",             - Represents whethter the tool generates the image for provisioning root key(0x01) or provisioning OTP key(0x0F)
    "BMCPFMOffset":"0x000E0000",        - BMC Active Offset with 4 bytes of Size
    "BMCActiveSize":"0x04000000",       - BMC Active Size with 4 bytes of size
    "BMCRecoveryOffset":"0x04000000",   - BMc Recovery Offset with 4 bytes of size
    "BMCRecoverySize":"0x04000000",     - BMC Recovery Size with 4 bytes of size
    "BMCStagingOffset":"0x08000000",    - BMC Staging Offset with 4 bytes of size
    "BMCStageSize":"0x04000000",        - BMC Stage size with 4 bytes of size
    "PCHPFMOffset":"0x00000000",        - PCH Active Offset with 4 bytes of Size
    "PCHActiveSize":"0x02000000",       - PCH Active Size with 4 bytes of size
    "PCHRecoveryOffset":"0x02000000",   - PCH Recovery Offset with 4 bytes of size
    "PCHRecoverySize":"0x02000000",     - PCH Recovery Size with 4 bytes of size
    "PCHStagingOffset":"0x00010000",    - PCH Staging Offset with 4 bytes of size
    "PCHStageSize":"0x00F00000",        - PCH Stage size with 4 bytes of size
    "RootKey":"pubkey_2048.pem",        - Public key file of the Root key
    "OTPSignKey":"prikey_2048.pem"   - Private key to sign the whole key image.
    }

   To provision the OTP Key, some more fields need to be added along with the JSON
    "Flag": "0x0F",         - Represents whethter the tool generates the image for provisioning root key(0x01) or provisioning OTP key(0x0F)
    "OTPKey":"otp_publickey.pem",   - Public key file of the OTP Key
    "OTP_Image":"otp_zephyr.bin"    - zephyr data to append in the provisioning Image

3. Please run the provisioning tool using the below command.
  3.a generate the provision root key image
    python3 provisioning_image_generator.py provisioning_image_generator_rootkey.ini

