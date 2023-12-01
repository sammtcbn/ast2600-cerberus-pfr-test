#!/bin/bash
# refer to openbmc/meta-aspeed-sdk/meta-ast2600-pfr/classes/cerberus-pfr-signing-image.bbclass

TOPPATH=$(cd "$(dirname "$1")"; pwd)

IMAGE_NAME=obmc-phosphor-image-ast2600-dcscm-amd
IMGDEPLOYDIR=${TOPPATH}/images

# PFR settings , copy from openbmc/meta-aspeed-sdk/meta-ast2600-pfr/conf/machine/ast2600-dcscm-amd.conf
PFR_IMAGE_SIZE="262144"
# 0x000E0000
PFM_OFFSET_PAGE="896"
# 0x04000000
RC_IMAGE_PAGE="65536"

# function copy from openbmc/meta-phosphor/classes/image_types_phosphor.bbclass
function mk_empty_image() {
    image_dst="$1"
    image_size_kb=$2
    dd if=/dev/zero bs=1k count=$image_size_kb | tr '\000' '\377' > $image_dst
}

# function copy from openbmc/meta-phosphor/classes/image_types_phosphor.bbclass
function mk_empty_image_zeros() {
    image_dst="$1"
    image_size_kb=$2
    dd if=/dev/zero of=$image_dst bs=1k count=$image_size_kb
}

PFR_IMAGES_DIR="${TOPPATH}/pfr_images"
PFR_IMAGE_BIN="image-mtd-pfr"

# PFR image generation script directory
PFR_MANIFEST_TOOLS_DIR="${TOPPATH}/manifest_tools"
PFR_RECOVERY_TOOLS_DIR="${TOPPATH}/recovery_tools"

#do_generate_signed_pfr_image(){
if [ -d ${PFR_IMAGES_DIR} ]; then
    rm -rf ${PFR_IMAGES_DIR}
fi

mkdir -p ${PFR_IMAGES_DIR}

# Assemble the flash image
mk_empty_image ${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN} ${PFR_IMAGE_SIZE}

dd bs=1k conv=notrunc seek=0 if=${IMGDEPLOYDIR}/${IMAGE_NAME}.static.mtd of=${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN} || exit 1

# create PFM manifest
rm -f ${PFR_MANIFEST_TOOLS_DIR}/${PFR_IMAGE_BIN}
rm -f ${PFR_MANIFEST_TOOLS_DIR}/obmc_pfm.bin
cp -f ${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN} ${PFR_MANIFEST_TOOLS_DIR} || exit 1
cd ${PFR_MANIFEST_TOOLS_DIR}
python3 pfm_generator.py obmc_pfm_generator.config
cp -f obmc_pfm.bin ${PFR_IMAGES_DIR}/.

# add the signed PFM to rom image
dd bs=1k conv=notrunc seek=${PFM_OFFSET_PAGE} if=${PFR_IMAGES_DIR}/obmc_pfm.bin of=${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN}

# create recovery image
rm -f ${PFR_RECOVERY_TOOLS_DIR}/${PFR_IMAGE_BIN}
rm -f ${PFR_RECOVERY_TOOLS_DIR}/obmc_recovery_image.bin
cp -f ${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN} ${PFR_RECOVERY_TOOLS_DIR}
cd ${PFR_RECOVERY_TOOLS_DIR}
python3 recovery_image_generator.py obmc_recovery_image_generator.config
cp -f obmc_recovery_image.bin ${PFR_IMAGES_DIR}/.

# add the signed recovery to rom image
dd bs=1k conv=notrunc seek=${RC_IMAGE_PAGE} if=${PFR_IMAGES_DIR}/obmc_recovery_image.bin of=${PFR_IMAGES_DIR}/${PFR_IMAGE_BIN}
