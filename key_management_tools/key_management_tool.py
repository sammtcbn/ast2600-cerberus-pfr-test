"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import sys
import traceback
import xml.etree.ElementTree as et
import binascii
import ctypes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512

IMAGE_CONFIG_FILENAME = "decommission_image_generator.config"

KEY_CANCELLATION_IMAGE_TYPE = int(4)
DECOMMISSION_IMAGE_TYPE = int(5)
KEY_MANIFEST_IMAGE_TYPE = int(6)

XML_VERSION_ATTRIB = "version"
XML_PLATFORM_ATTRIB = "platform"
XML_TYPE_ATTRIB = "type"
XML_HASH_TYPE_TAG = "HashType"
XML_KEY_TAG = "Key"
XML_CANCELLATION_SECTION_TAG = "CancellationSection"
XML_CANCELLATION_POLICY_TAG = "CancellationPolicy"
XML_MANIFEST_SECTION_TAG = "KeyManifestSection"

IMAGE_MAGIC_NUM = int("0xb6eafd19", 16)
IMAGE_SECTION_MAGIC_NUM = int("0xf27f28d7", 16)
IMAGE_SECTION_FORMAT_NUM = 0
IMAGE_MAX_SIZE = 134217728
IMAGE_MAX_VERSION_ID_SIZE = 32


KEY_CANCEL_MAGIC_NUM = int("0x4b455943", 16)
KEY_PROV_MAGIC_NUM = int("0x6b65796d", 16)

SHA256_HASH_LEN = 32
SHA384_HASH_LEN = 48
SHA512_HASH_LEN = 64
SHA_MAX_HASH_LEN = SHA512_HASH_LEN

PUB_KEY_HASH_FILE_SUFFIX = ".hash.bin"
PUB_KEY_RAW_FILE_SUFFIX = ".raw.bin"
MAX_SIGNING_KEYS = 8

RSA2048_SIG_LEN = 256
RSA3072_SIG_LEN = 384
RSA4096_SIG_LEN = 512
RSA_MAX_SIG_LEN = RSA4096_SIG_LEN

# KEY CANCELLATION POLICY
ROT_CANCELLATION = 0x100
PCH_CANCELLATION = 0x101
BMC_CANCELLATION = 0x103

class rsa_pub_key_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('modulus', ctypes.c_ubyte * RSA_MAX_SIG_LEN),
                ('mod_length', ctypes.c_uint),
                ('exponent', ctypes.c_uint)]
    def __init__(self, modulus, m_length, exponent):
        self.mod_length = m_length
        self.exponent = exponent
        ctypes.memset(ctypes.byref(self.modulus), 0xff, ctypes.sizeof(self.modulus))
        ctypes.memmove(ctypes.byref(self.modulus), modulus, self.mod_length)

class image_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('header_length', ctypes.c_ushort),
                ('type', ctypes.c_ushort),
                ('marker', ctypes.c_uint),
                ('version_id', ctypes.c_ubyte * 32),
                ('image_length', ctypes.c_uint),
                ('sig_length', ctypes.c_uint)]

class image_section_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('header_length', ctypes.c_ushort),
                ('format', ctypes.c_ushort),
                ('marker', ctypes.c_uint),
                ('addr', ctypes.c_uint),
                ('section_length', ctypes.c_uint)]

class key_cancel_info(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('key_id', ctypes.c_ubyte),
                ('key_hash', ctypes.c_ubyte * SHA_MAX_HASH_LEN)]

class key_cancellation_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('marker', ctypes.c_uint),
                ('key_policy', ctypes.c_ushort),
                ('hash_type', ctypes.c_ubyte),
                ('key_count', ctypes.c_ubyte),
                ('key_can_list', key_cancel_info * MAX_SIGNING_KEYS)]

    def __init__(self, marker, key_policy, hash_type, key_count):
        self.marker = marker
        self.key_policy = key_policy
        self.hash_type = hash_type
        self.key_count = key_count
        ctypes.memset(ctypes.byref(self.key_can_list), 0xff, ctypes.sizeof(self.key_can_list))

class key_provision_info(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('key_hash', ctypes.c_ubyte * SHA_MAX_HASH_LEN)]

class key_manifest_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('marker', ctypes.c_uint),
                ('hash_type', ctypes.c_ubyte),
                ('key_count', ctypes.c_ubyte),
                ('key_list', key_provision_info * MAX_SIGNING_KEYS)]

    def __init__(self, marker, hash_type, key_count):
        self.marker = marker
        self.hash_type = hash_type
        self.key_count = key_count
        ctypes.memset(ctypes.byref(self.key_list), 0xff, ctypes.sizeof(self.key_list))

def xml_find_single_tag (root, tag_name):
    """
    Fetch an XML tag from XML.

    :param root: XML to utilize
    :param tag_name: Name of tag to fetch

    :return Tag if found
    """

    tag = root.findall (tag_name)
    if len(tag) != 1:
        raise ValueError ("Too many {0} tags in manifest {1} or tag not found".format (tag_name, root))

    return tag[0]

def get_key_hash_type(section):
    hash_alg = xml_find_single_tag(section, XML_HASH_TYPE_TAG).text.strip()
    if (hash_alg == "SHA256"):
        hash_type = 1
        hash_len = SHA256_HASH_LEN
    elif (hash_alg == "SHA384"):
        hash_type = 2
        hash_len = SHA384_HASH_LEN
    elif (hash_alg == "SHA512"):
        hash_type = 3
        hash_len = SHA512_HASH_LEN
    else:
        raise ValueError ("Unknown hash type '{0}'".format (hash_alg))

    return hash_type, hash_len

def process_key_cancellation(root, xml):
    """
    Parse key cancellation related attributes.

    :param root: XML to utilize
    :param xml: List of parsed XML image data
    """

    section = xml_find_single_tag(root, XML_CANCELLATION_SECTION_TAG)
    key_policy_tag = xml_find_single_tag(section, XML_CANCELLATION_POLICY_TAG).text.strip()
    if (key_policy_tag == "BMC"):
        key_policy = BMC_CANCELLATION
    elif (key_policy_tag == "PCH"):
        key_policy = PCH_CANCELLATION
    elif (key_policy_tag == "ROT"):
        key_policy = ROT_CANCELLATION
    else:
        raise ValueError ("Unknown key cancellation policy '{0}'".format (key_policy_tag))

    hash_type, hash_len = get_key_hash_type(section)

    keys = section.findall(XML_KEY_TAG)
    key_count = len(keys)
    if key_count > 8:
        raise ValueError ("Key count: '{0}' exceed the maximum count: 8".format (key_count))
    elif key_count <= 0:
        raise ValueError ("Key is not found, key_count is '{0}'".format(key_count))

    key_cancellation_inst = key_cancellation_struct(KEY_CANCEL_MAGIC_NUM,
            key_policy, hash_type, key_count)
    key_list_idx = 0

    if "cancel_key" in G_Config and G_Config["cancel_key"]:
        for cancel_key_path in G_Config["cancel_key"]:
            generate_public_key_hash(cancel_key_path, hash_type)

    for key in keys:
        key_id = xml_find_single_tag(key, "KeyId").text.strip()
        key_cancellation_inst.key_can_list[key_list_idx].key_id = int(key_id)

        pubkey_hash_file = xml_find_single_tag(key, "PublicKey").text.strip()
        pubkey_hash_file += PUB_KEY_HASH_FILE_SUFFIX
        with open(pubkey_hash_file, "rb") as f:
            pubkey_hash = f.read()
            ctypes.memmove(key_cancellation_inst.key_can_list[key_list_idx].key_hash,
                           pubkey_hash,
                           hash_len)
        key_list_idx += 1

    xml["key_cancellation"] = key_cancellation_inst

def process_key_manifest(root, xml):
    """
    Parse key manifest related attributes.

    :param root: XML to utilize
    :param xml: List of parsed XML image data
    """

    section = xml_find_single_tag(root, XML_MANIFEST_SECTION_TAG)
    hash_type, hash_len = get_key_hash_type(section)

    keys = section.findall(XML_KEY_TAG)
    key_count = len(keys)
    if key_count > 8:
        raise ValueError ("Key count: '{0}' exceed the maximum count: 8".format (key_count))
    elif key_count <= 0:
        raise ValueError ("Key is not found, key_count is '{0}'".format(key_count))

    key_manifest_inst = key_manifest_struct(KEY_PROV_MAGIC_NUM, hash_type, key_count)
    key_list_idx = 0

    if "signing_key" in G_Config and G_Config["signing_key"]:
        for signing_key_path in G_Config["signing_key"]:
            generate_public_key_hash(signing_key_path, hash_type)

    for key in keys:
        pubkey_hash_file = xml_find_single_tag(key, "PublicKey").text.strip()
        pubkey_hash_file += PUB_KEY_HASH_FILE_SUFFIX
        with open(pubkey_hash_file, "rb") as f:
            pubkey_hash = f.read()
            ctypes.memmove(key_manifest_inst.key_list[key_list_idx].key_hash,
                           pubkey_hash,
                           hash_len)
        key_list_idx += 1

    xml["key_manifest"] = key_manifest_inst

def process_image(root):
    """
    Process the tree storing the image data starting with the root element

    :param root: The root element for the tree storing the XML image data

    :return dictionary of the processed image data
    """

    xml = {}

    version_id = root.attrib.get(XML_VERSION_ATTRIB)
    type_xml = root.attrib.get(XML_TYPE_ATTRIB)

    if (version_id in (None, "") or (len(version_id) > (IMAGE_MAX_VERSION_ID_SIZE - 1))):
        raise ValueError("Invalid or no image version ID provided")

    platform_id = root.attrib.get(XML_PLATFORM_ATTRIB)

    if platform_id in (None, ""):
        raise ValueError("No Platform ID provided")

    padding = b'\x00'
    xml["version_id"] = version_id.strip().encode("utf8")
    xml["version_id"] += padding * (32 - len(xml["version_id"]))
    xml["platform_id"] = platform_id.strip().encode("utf8")
    xml["type"] = int(type_xml)

    if xml["type"] < KEY_CANCELLATION_IMAGE_TYPE or xml["type"] > KEY_MANIFEST_IMAGE_TYPE:
        raise ValueError("Invalid number of type in the image: {0}".format(xml["type"]))

    if xml["type"] == KEY_CANCELLATION_IMAGE_TYPE:
        process_key_cancellation(root, xml)
    elif xml["type"] == KEY_MANIFEST_IMAGE_TYPE:
        process_key_manifest(root, xml)

    return xml


def load_config(config_file):
    """
    Load configuration options from file

    :param config_file: Path for a text file containing config options

    :return parsed configuration
    """

    config = {}
    config["xml"] = ""
    config["output"] = ""
    config["input"] = ""
    config["prv_key_path"] = ""
    config["cancel_key"] = []
    config["signing_key"] = []

    with open(config_file, 'r') as fh:
        data = fh.readlines()

    if not data:
        print("Failed to load configuration")
        sys.exit(1)

    for string in data:
        string = string.replace("\n", "")
        string = string.replace("\r", "")

        if string.startswith("Output"):
            config["output"] = string.split("=")[-1].strip()
        elif string.startswith("Key"):
            config["prv_key_path"] = string.split("=")[-1].strip()
        elif string.startswith("Xml"):
            config["xml"] = string.split("=")[-1].strip()
        elif string.startswith("Cancel_Key"):
            config["cancel_key"].append(string.split("=")[-1].strip())
        elif string.startswith("Signing_Key"):
            config["signing_key"].append(string.split("=")[-1].strip())

    return config


def load_and_process_xml(xml_file):
    """
    Process the XML file storing the image data

    :param xml_file: Name of XML file storing the image data

    :return dictionary of the processed image data
    """

    root = et.parse(xml_file).getroot()
    return process_image(root)


def get_image_len(img_type, sig_len):
    """
    Calculate the image length from the processed image data. The total includes
    the headers, image(s), and signature.

    :param img_type: The type of generated image
    :param sig_len: The image signature length

    :return the total length of the image
    """

    header_len = ctypes.sizeof(full_image_header)
    image_sec_header_len = ctypes.sizeof(image_section_header)

    if img_type == KEY_CANCELLATION_IMAGE_TYPE:
        section_len = ctypes.sizeof(key_cancellation_struct)
    elif img_type == KEY_MANIFEST_IMAGE_TYPE:
        section_len = ctypes.sizeof(key_manifest_struct)
    elif img_type == DECOMMISSION_IMAGE_TYPE:
        section_len = 0
    else:
        raise ValueError ("Unknown image type {0}".format (img_type))

    return header_len + image_sec_header_len + section_len + sig_len

def generate_key_cancellation_image(xml, image_header_inst):
    """
    Generate key cancellation image.

    :param xml: List of parsed XML image data
    :param image_header_inst: Image header

    :return Key cancellation image instance
    """

    image_sections_inst = image_section_header(ctypes.sizeof(image_section_header),
            IMAGE_SECTION_FORMAT_NUM,
            IMAGE_SECTION_MAGIC_NUM,
            0, ctypes.sizeof(key_cancellation_struct))

    class key_cancellation_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('full_image_header', full_image_header),
                    ('image_section_header', image_section_header),
                    ('key_cancellation_image', key_cancellation_struct)]

    return key_cancellation_img(fuill_image_header_inst, image_sections_inst,
            xml["key_cancellation"])

def generate_key_manifest_image(xml, image_header_inst):
    """
    Generate key manifest image.

    :param xml: List of parsed XML image data
    :param image_header_inst: Image header

    :return Key manifest image instance
    """

    image_sections_inst = image_section_header(ctypes.sizeof(image_section_header),
            IMAGE_SECTION_FORMAT_NUM,
            IMAGE_SECTION_MAGIC_NUM,
            0, ctypes.sizeof(key_manifest_struct))

    class key_manifest_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('full_image_header', full_image_header),
                    ('image_section_header', image_section_header),
                    ('key_manifest', key_manifest_struct)]

    return key_manifest_img(fuill_image_header_inst, image_sections_inst,
            xml["key_manifest"])

def generate_decommission_image(xml, image_header_inst):
    """
    Generate decommission image.

    :param xml: List of parsed XML image data
    :param image_header_inst: Image header

    :return decommission image instance
    """

    image_sections_inst = image_section_header(ctypes.sizeof(image_section_header),
            IMAGE_SECTION_FORMAT_NUM,
            IMAGE_SECTION_MAGIC_NUM,
            0, 0)

    class decommission_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('full_image_header', full_image_header),
                    ('image_section_header', image_section_header)]

    return decommission_img(fuill_image_header_inst, image_sections_inst)

def generate_image(xml, img_type, image_header_inst, root_pub_key, root_priv_key):
    """
    Create a image object from all the different image components

    :param xml: List of parsed XML image data
    :param img_type: Image type
    :param image_header_inst: Instance of a image header
    :param root_pub_key: Root public key in struct rsa_pub_key{} format
    :param root_priv_key: Root private key for signing image

    :return Instance of a signed image bytearray
    """

    if img_type == KEY_CANCELLATION_IMAGE_TYPE:
        # struct key_cancellation_manifest {
        #     struct recovery_header image_header;
        #     struct recovery_section image_section;
        #     struct key_cancellation{
        #             uint32_t magic_number;   // 0x4b455943   'KEYC'
        #             uint16_t key_policy;     // 0x0100 = ROT, 0x0101 = PCH, 0x0103 = BMC
        #             uint8_t hash_type;       // 1: 256(default); 2: 384; 3: 512
        #             uint8_t key_count;       // 8(maximum)
        #             struct key_cancel_list {
        #                     uint8_t key_id;
        #                     uint8_t key_hash[64];
        #             } key_cancel_list[key_count]
        #     }
        #     uint8_t signature[];              // rsa2048: 256 bytes;
        #     struct rsa_public_key {
        #             uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
        #             size_t mod_length;
        #             uint32_t exponent;
        #     } root_pub_key;
        # };
        generated_image = generate_key_cancellation_image(xml, image_header_inst)
    elif img_type == KEY_MANIFEST_IMAGE_TYPE:
        # struct key_provision_manifest {
        #     struct recovery_header image_header;
        #     struct recovery_section image_section;
        #     struct key_cancellation{
        #             uint32_t magic_number;   // 0x6b65796d   'keym'
        #             uint8_t hash_type;       // 1: 256(default); 2: 384; 3: 512
        #             uint8_t key_count;       // 8(maximum)
        #             struct key_list {
        #                     uint8_t key_hash[64];
        #             } key_list[key_count]
        #     }
        #     uint8_t signature[];              // rsa2048: 256 bytes;
        #     struct rsa_public_key {
        #             uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
        #             size_t mod_length;
        #             uint32_t exponent;
        #     } root_pub_key;
        # };
        generated_image = generate_key_manifest_image(xml, image_header_inst)
    elif img_type == DECOMMISSION_IMAGE_TYPE:
        # struct decommission {
        #     struct recovery_header image_header;
        #     struct recovery_section image_section;
        #     uint8_t signature[];              // rsa2048: 256 bytes;
        #     struct rsa_public_key {
        #             uint8_t modulus[RSA_MAX_KEY_LENGTH]; // 512 bytes
        #             size_t mod_length;
        #             uint32_t exponent;
        #     } root_pub_key;
        # };
        generated_image = generate_decommission_image(xml, image_header_inst)
    else:
        raise ValueError ("Unknown image type {0}".format (img_type))

    generated_image_bytes = bytearray(generated_image)
    h = SHA256.new(generated_image_bytes)
    signer = PKCS1_v1_5.new(root_priv_key)
    signature = signer.sign(h)
    signed_image = generated_image_bytes + signature + bytearray(root_pub_key)

    if (len(signed_image) > IMAGE_MAX_SIZE):
        raise ValueError ("Generated image is too large - {0}".format (len(signed_image)))

    return signed_image

def load_key(prv_key_path):
    """
    Load private RSA key to sign the image from the provided path. If no valid key can be
    imported, key size will be what is provided. Otherwise, key size will be size of key imported.

    :param prv_key_path: Provided private key path

    :return <Sign image or not> <Key to use for signing>
    """

    if prv_key_path:
        try:
            key = RSA.importKey(open(prv_key_path).read())
        except Exception:
            print("Unsigned image will be generated, provided RSA key could not be imported: {0}".format(prv_key_path))
            traceback.print_exc()
            return False, None, None

        return True, int(key.n.bit_length() / 8), key
    else:
        print("No RSA private key provided in config, unsigned image will be generated.")
        return False, None, None

def generate_public_key_hash(key_path, hash_type):
    """
    Generate hash of cerberus rsa_pub_key struct and stored in a file.

    :param key_path: Provided public key path
    """

    try:
        key_hash_path = key_path + PUB_KEY_HASH_FILE_SUFFIX
        key_raw_path = key_path + PUB_KEY_RAW_FILE_SUFFIX
        key = RSA.importKey(open(key_path).read())
        mod_fmt = "%%0%dx" % (key.n.bit_length() // 4)
        modulus = binascii.a2b_hex(mod_fmt % key.n)
        exponent = int(key.e)
        mod_length = len(modulus)
        rsa_pub_key_inst = rsa_pub_key_struct(modulus, mod_length, exponent)
        with open(key_raw_path, 'wb+') as fh:
            fh.write(rsa_pub_key_inst)

        if hash_type == 1:
            h = SHA256.new(bytearray(rsa_pub_key_inst))
        elif hash_type == 2:
            h = SHA384.new(bytearray(rsa_pub_key_inst))
        elif hash_type == 3:
            h = SHA512.new(bytearray(rsa_pub_key_inst))
        else:
            h = SHA256.new(bytearray(rsa_pub_key_inst))
        with open(key_hash_path, 'wb+') as fh:
            fh.write(h.digest())

    except Exception as e:
        print(e)

# *************************************** Start of Script ***************************************

if len(sys.argv) < 2:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), IMAGE_CONFIG_FILENAME)
else:
    path = os.path.abspath(sys.argv[1])

G_Config = load_config(path)
prv_key_path = None

if "prv_key_path" in G_Config and G_Config["prv_key_path"]:
    prv_key_path = G_Config["prv_key_path"]

sign, key_size, key = load_key(prv_key_path)

if (key_size is None):
    print("invalid root key")
    os._exit(1)

if (key is None):
    print("invalid root key")
    os._exit(1)

if sign is True:
    mod_fmt = "%%0%dx" % (key.n.bit_length() // 4)
    modulus = binascii.a2b_hex(mod_fmt % key.n)
    exponent = int(key.e)
    mod_length = len(modulus)
    RootPubKey = rsa_pub_key_struct(modulus, mod_length, exponent)
else:
    print("generating unsigned image is not supported")
    os._exit(1)

sig_len = key_size
processed_xml = load_and_process_xml(G_Config["xml"])
img_type = processed_xml['type']
platform_id_len = len(processed_xml["platform_id"])

class full_image_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('image_header', image_header),
                ('platform_id_length', ctypes.c_ubyte),
                ('platform_id', ctypes.c_ubyte * platform_id_len)]

header_len = ctypes.sizeof(full_image_header)
image_len = get_image_len(img_type, sig_len)
version_id_buf = (ctypes.c_ubyte * len(processed_xml["version_id"])).from_buffer_copy(processed_xml["version_id"])

image_header_inst = image_header(header_len,
                                 img_type,
                                 IMAGE_MAGIC_NUM,
                                 version_id_buf,
                                 image_len,
                                 sig_len)

platform_id_buf = (ctypes.c_ubyte * len(processed_xml["platform_id"])).from_buffer_copy(processed_xml["platform_id"])

fuill_image_header_inst = full_image_header(image_header_inst,
                                            platform_id_len,
                                            platform_id_buf)

signed_image = generate_image(processed_xml, img_type, fuill_image_header_inst, RootPubKey, key)

with open(G_Config["output"], 'wb') as fs:
    fs.write(signed_image)

print("Completed image generation: {0}".format(G_Config["output"]))
