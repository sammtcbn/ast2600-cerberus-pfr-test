1. The recovery tool creates the recovery and update image with the recovery header and the recovery data.
   The recovery and update image is signed by CSK key.
2. Please configure the config files with the valid data.
3. This tool requires the input XML file and this file has the type of the image, recovery sections details.
4. The valid values for type that can be provided in the xml are as follows,
        BMC: 00 00
        PCH: 01 00
        ROT: 02 00
5.  Below is the structure of the recovery image file.
        header -
                header_length=2 bytes(Total header length)
                type=2 bytes
                magic=4 bytes(magic number to identify the header)
                version_id=32 bytes(coming from xml file)
                image_length=4 bytes(total file length)
                sig_length=4 bytes
                platform_id_length=1 byte
                platform_id=length varies based on xml file
        recoveryimagesectionlist-
                Headderlength=2 bytes(recovery image section header length)
                format=2 bytes(reserved)
                magic=4 bytes(magicnumber to identify the recovery header)
                address=4 bytes(coming from xml file)
                imagelength=4 bytes(encoded data coming from xml file)
                imagedata=data(data coming from xml)
        Signature=256 bytes
        csk_pub_key=520 bytes

    5.1 Recovery and Update Image structure:
        ```
        struct recovery_image {
            struct recovery_header
            struct recovery_image_section_lists {
                struct recovery_section
                u8 imagedata[imagelength]
            }
            u8 signature[sig_length]
            struct rsa_public_key {
                uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
                size_t mod_length;
                uint32_t exponent;
            } csk_pub_key;
        }
        ```
6. Use the version attribute of the XML to emulate the SVN only for ROT type. Please note, both bmc and pch svn, major and minor version are set in pfm.
   The version attribute as below.
   Version is 00.01.06 (SVN:00, Major: 01, Minor:06)
   ```
   <RecoveryImage version="00.01.06" platform="rot" type="2">
   ```
   By default, the version string is in ASCII code data, changes the data format to hex data. SVN should be between 00-64 and the version length is 6.
   6.1 rot version structure:
       ```
       struct rot_version {
           uint8_t svn;
           uint8_t reserved1;
           uint8_t major;
           uint8_t reserved2;
           uint8_t minor;
           uint8_t reserved3;
       }
       ```
7. To generate the recovery image, please run the python script as follows,
        python3 recovery_image_generator.py
