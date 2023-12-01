#!/bin/bash
TOPPATH=$(cd "$(dirname "$1")/.."; pwd)

# -----------------------------------------------

CERBERUS_BRANCH=aspeed-master
CERBERUS_TAG=v01.06

OPENBMC_TAG=v08.06

#output=./output
output=${TOPPATH}

# -----------------------------------------------

mkdir -p ${output} || exit 1

CERBERUS_PATH=${TOPPATH}/cerberus
OPENBMC_PATH=${TOPPATH}/openbmc

function aspeed-cerberus-tools-dl()
{
  cd ${TOPPATH} || exit 1
  git clone https://github.com/AspeedTech-BMC/cerberus.git || exit 1
  cd cerberus || exit 1
  git checkout ${CERBERUS_TAG} || exit 1
}

function aspeed-openbmc-dl()
{
  cd ${TOPPATH} || exit 1
  git clone https://github.com/AspeedTech-BMC/openbmc.git || exit 1
  cd openbmc || exit 1
  git checkout ${OPENBMC_TAG} || exit 1
}


function collect ()
{
mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-provision-image/cerberus-pfr-provision-image/provision_tools/* ${CERBERUS_PATH}/tools/provision_tools || exit 1

mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-provision-image/cerberus-pfr-provision-image/key_management_tools/* ${CERBERUS_PATH}/tools/key_management_tools || exit 1

mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/manifest_tools/* ${CERBERUS_PATH}/tools/manifest_tools || exit 1

mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/recovery_tools/* ${CERBERUS_PATH}/tools/recovery_tools || exit 1

cp -f ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/keys/* ${CERBERUS_PATH}/tools/recovery_tools || exit 1

cp -f ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/keys/* ${CERBERUS_PATH}/tools/manifest_tools || exit 1

cp -f ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/keys/* ${CERBERUS_PATH}/tools/provision_tools || exit 1

cp -f ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/keys/* ${CERBERUS_PATH}/tools/key_management_tools || exit 1

rm -f ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-signing-utility/cerberus-pfr-signing-utility/keys/* || exit 1

mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-key-manifest-image/cerberus-pfr-key-manifest-image/key_management_tools/* ${CERBERUS_PATH}/tools/key_management_tools || exit 1

mv ${OPENBMC_PATH}/meta-aspeed-sdk/meta-ast2600-pfr/recipes-cerberus/cerberus-pfr-key-cancellation-image/cerberus-pfr-key-cancellation-image/key_management_tools/* ${CERBERUS_PATH}/tools/key_management_tools || exit 1
}

function copy_output()
{
  rm -rf ${output}/key_management_tools || exit 1
  rm -rf ${output}/manifest_tools || exit 1
  rm -rf ${output}/manifest_visualizer || exit 1
  rm -rf ${output}/ocp_recovery || exit 1
  rm -rf ${output}/provision_tools || exit 1
  rm -rf ${output}/recovery_tools || exit 1
  rm -rf ${output}/testing || exit 1

  mv ${CERBERUS_PATH}/tools/key_management_tools ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/manifest_tools ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/manifest_visualizer ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/ocp_recovery ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/provision_tools ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/recovery_tools ${output} || exit 1
  mv ${CERBERUS_PATH}/tools/testing ${output} || exit 1
}

function shrink_file()
{
  cd ${TOPPATH} || exit 1
  rm -f ${output}/recovery_tools/recovery_image_generator.config || exit 1
  find recovery_tools  -name "*.pem" ! -name "pricsk0_2048.pem" -exec rm -r {} \;
  find provision_tools -name "*.pem" ! -name "prikey_2048.pem" ! -name "pubkey_2048.pem" -exec rm -r {} \;
  find manifest_tools  -name "*.pem" ! -name "prikey_2048.pem" ! -name "pricsk0_2048.pem" -exec rm -r {} \;
}

function clean_metafile()
{
  rm -rf ${CERBERUS_PATH} || exit 1
  rm -rf ${OPENBMC_PATH} || exit 1
}

aspeed-cerberus-tools-dl
aspeed-openbmc-dl
collect
copy_output
shrink_file
clean_metafile

echo done
