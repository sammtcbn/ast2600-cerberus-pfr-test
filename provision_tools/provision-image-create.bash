#!/bin/bash
# refer to openbmc/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-provision-image/cerberus-pfr-provision-image.bb
TOPPATH=$(cd "$(dirname "$1")/.."; pwd)

PFR_PROVISION_TOOLS_DIR="${TOPPATH}/provision_tools"
PFR_KEY_MANAGEMENT_TOOLS_DIR="${TOPPATH}/key_management_tools"

# Provision image size is 4KB
# offset    0 - 2047 : provisioning information(Root key, BMC/PCH firmware offset, ... etc.)
# offset 2048 - 4095 : key manifest image
PROVISION_IMAGE_SIZE="4"

rm -f ${PFR_PROVISION_TOOLS_DIR}/*.bin

cd ${PFR_KEY_MANAGEMENT_TOOLS_DIR}
python3 key_management_tool.py key_manifest0_image.config

cd ${PFR_PROVISION_TOOLS_DIR}
python3 provisioning_image_generator.py provisioning_image_generator_rootkey.ini

dd if=/dev/zero bs=1k count=${PROVISION_IMAGE_SIZE} | tr '\000' '\377' > ${PFR_PROVISION_TOOLS_DIR}/final_provision.bin

dd bs=1 conv=notrunc seek=0 if=${PFR_PROVISION_TOOLS_DIR}/provision_rootkey.bin of=${PFR_PROVISION_TOOLS_DIR}/final_provision.bin

dd bs=1 conv=notrunc seek=2048 if=${PFR_KEY_MANAGEMENT_TOOLS_DIR}/key_manifest0_image.bin of=${PFR_PROVISION_TOOLS_DIR}/final_provision.bin
