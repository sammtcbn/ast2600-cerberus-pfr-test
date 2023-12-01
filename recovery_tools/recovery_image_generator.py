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
import re
import ctypes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


RECOVERY_IMAGE_CONFIG_FILENAME = "recovery_image_generator.config"

XML_VERSION_ATTRIB = "version"
XML_PLATFORM_ATTRIB = "platform"
XML_TYPE_ATTRIB = "type"

XML_RECOVERY_SECTION_TAG = "RecoverySection"
XML_REGION_TAG = "Region"
XML_WRITE_ADDRESS_TAG = "WriteAddress"
XML_ENCODED_IMAGE_TAG = "EncodedImage"
XML_START_ADDR_TAG = "StartAddr"
XML_END_ADDR_TAG = "EndAddr"

RECOVERY_IMAGE_MAGIC_NUM = int("0x8a147c29", 16)
RECOVERY_IMAGE_SECTION_MAGIC_NUM = int("0x4b172f31", 16)
# RECOVERY_IMAGE_FORMAT_NUM = 0
RECOVERY_IMAGE_SECTION_FORMAT_NUM = 0
RECOVERY_IMAGE_SECTION_HEADER_LENGTH = 16
RECOVERY_IMAGE_MAX_SIZE = 134217728
RECOVERY_IMAGE_MAX_VERSION_ID_SIZE = 32
RECOVERY_IMAGE_ROT_TYPE = 2

RSA2048_SIG_LEN = 256
RSA3072_SIG_LEN = 384
RSA4096_SIG_LEN = 512
RSA_MAX_SIG_LEN = RSA4096_SIG_LEN


class recovery_image_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('header_length', ctypes.c_ushort),
                ('type', ctypes.c_ushort),
                ('marker', ctypes.c_uint),
                ('image_length', ctypes.c_uint),
                ('sig_length', ctypes.c_uint),
                ('platform_id_length', ctypes.c_ubyte)]


class recovery_image_section_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('header_length', ctypes.c_ushort),
                ('format', ctypes.c_ushort),
                ('marker', ctypes.c_uint),
                ('addr', ctypes.c_uint),
                ('image_length', ctypes.c_uint)]


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


# This version format only used for rot not including bmc and pch
# Both bmc and pch svn, major and minor version are set in pfm
# Version Format SVN(XX).Major(XX).Minor(XX)
# SVN should be between 00-64
class rot_version_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('svn', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('major', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte),
                ('minor', ctypes.c_ubyte),
                ('reserved3', ctypes.c_ubyte)]
    def __init__(self, svn, major, minor):
        self.svn = svn
        self.major = major
        self.minor = minor
        self.reserved1 = 0
        self.reserved2 = 0
        self.reserved3 = 0


def process_recovery_image(root):
    """
    Process the tree storing the recovery image data starting with the root element

    :param root: The root element for the tree storing the XML recovery image data

    :return dictionary of the processed recovery image data    
    """

    xml = {}

    version_id = root.attrib.get(XML_VERSION_ATTRIB)
    type_xml = root.attrib.get(XML_TYPE_ATTRIB)

    if (version_id in (None, "") or (len(version_id) > (RECOVERY_IMAGE_MAX_VERSION_ID_SIZE - 1))):
        raise ValueError("Invalid or no recovery image version ID provided")

    if (int(type_xml) == RECOVERY_IMAGE_ROT_TYPE):
        pattern = r'^([0-5]{1}[0-9]{1}|6[0-4]{1})\.(\d{2})\.(\d{2})$'
        if not re.match(pattern, version_id):
            raise ValueError ("Invalid version format: {0}, Expected version format: SVN(XX).Major(XX).Minor(XX) decimal digit and SVN valid range: 00-64".format (
                version_id))

    platform_id = root.attrib.get(XML_PLATFORM_ATTRIB)

    if platform_id in (None, ""):
        raise ValueError("No Platform ID provided")

    xml["version_id"] = version_id.strip().encode("utf8")
    xml["platform_id"] = platform_id.strip().encode("utf8")
    xml["type"] = int(type_xml)

    sections = root.findall(XML_RECOVERY_SECTION_TAG)

    if not sections:
        raise ValueError("Invalid number of RecoverySections tags in recovery image: {0}".format(
            xml["version_id"]))

    xml["sections"] = []
    with open(input_bin_path, "rb") as f:
        imagedata = f.read()
    for s in sections:
        recoverydata = b""
        recovery_section = {}
        write_addr = s.findall(XML_WRITE_ADDRESS_TAG)

        if not write_addr or len(write_addr) > 1:
            raise ValueError("Invalid number of WriteAddress tags in recovery image: {0}".format(
                xml["version_id"]))
            
        recovery_section["addr"] = write_addr[0].text.strip()
        regions = s.findall(XML_REGION_TAG)
        for region in regions:
            startaddress = region.findall(XML_START_ADDR_TAG)[0].text.strip()
            endaddress = region.findall(XML_END_ADDR_TAG)[0].text.strip()
            recoverydata = recoverydata + imagedata[int(startaddress, 16):int(endaddress, 16) + 1]

        recovery_section["image"] = recoverydata
        xml["sections"].append(recovery_section)

        '''
        encoded_image = s.findall(XML_ENCODED_IMAGE_TAG)
        if not encoded_image or len(encoded_image) > 1:
            raise ValueError("Invalid number of EncodedImage tags in recovery image: {0}".format(
                xml["version_id"]))

        recovery_section["image"] = binascii.a2b_base64(re.sub("\s", "",
            encoded_image[0].text.strip()))

        if len(xml["sections"]) == 0:
            xml["sections"].append(recovery_section)
        else:
            ind = 1
            for sec in xml["sections"]:
                if sec["addr"] > recovery_section["addr"]:
                    xml["sections"].insert(ind - 1, recovery_section)
                    break
                elif sec["addr"] == recovery_section["addr"]:
                    raise ValueError("Invalid WriteAddress in recovery image section: {0}".format(
                        recovery_section["addr"]))
                elif ind == len(xml["sections"]):
                    xml["sections"].append(recovery_section)
                    break
                ind += 1
        '''

    if not xml["sections"]:
        raise ValueError("No recovery sections found for recovery image: {0}".format(xml["version_id"]))

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
    config["input"]=""
    config["prv_key_path"] = ""
    config["key_size"] = ""

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
        elif string.startswith("InputImage"):
            config["input"] = string.split("=")[-1].strip()
        elif string.startswith("KeySize"):
            config["key_size"] = string.split("=")[-1].strip()
        elif string.startswith("Key"):
            config["prv_key_path"] = string.split("=")[-1].strip()
        elif string.startswith("Xml"):
            config["xml"] = string.split("=")[-1].strip()

    return config

def load_and_process_xml(xml_file):
    """
    Process the XML file storing the recovery image data

    :param xml_file: Name of XML file storing the recovery image data 

    :return dictionary of the processed recovery image data
    """

    root = et.parse(xml_file).getroot()
    return process_recovery_image(root)

def get_recovery_image_len(xml, sig_len):
    """
    Calculate the recovery image length from the processed recovery image data. The total includes
    the headers, image(s), and signature.

    :param xml: The processed recovery image data
    :param sig_len: The recovery image signature length 

    :return the total length of the recovery image 
    """
    
    header_len = ctypes.sizeof(recovery_image_header) + RECOVERY_IMAGE_MAX_VERSION_ID_SIZE + len(xml["platform_id"])

    image_lens = 0
    for section in xml["sections"]:
        image_lens += len(section["image"]) + 16

    return header_len + image_lens + sig_len

def generate_recovery_image_section_instance(section):
    """
    Create a recovery image section
    
    :param section: The recovery image section data

    :return instance of a recovery image section
    """

    addr = int(section["addr"], 16)
    section_header = recovery_image_section_header(RECOVERY_IMAGE_SECTION_HEADER_LENGTH,
        RECOVERY_IMAGE_SECTION_FORMAT_NUM, RECOVERY_IMAGE_SECTION_MAGIC_NUM, addr,
        len(section["image"]))
    img_array = (ctypes.c_ubyte * len(section["image"])).from_buffer_copy(section["image"])

    class recovery_image_section(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', recovery_image_section_header),
                    ('img', ctypes.c_ubyte * len(section["image"]))]

    return recovery_image_section(section_header, img_array)

def generate_recovery_image_section_list(xml):
    """
    Create a list of recovery image sections from the parsed XML list

    :param xml: List of parsed XML recovery image data

    :return list of recovery image section instances
    """
    
    section_list = []    
    min_addr = -1

    for s in xml["sections"]:
        sec_addr = int(s["addr"], 16)
        if  sec_addr <= min_addr:
            raise ValueError("Invalid WriteAddress in recovery image section: {0}".format(
                s["addr"]))
        section = generate_recovery_image_section_instance(s)
        section_list.append(section)
        min_addr = sec_addr + len(s["image"]) - 1

    return section_list

def generate_recovery_image(xml, recovery_image_header_instance, recovery_image_sections_list):
    """
    Create a recovery image object from all the different recovery image components

    :param xml: List of parsed XML recovery image data
    :param recovery_image_header_instance: Instance of a recovery image header
    :param recovery_image_sections_list: List of recovery image sections to be included in the
    recovery image

    :return Instance of a recovery image object
    """

    sections_size = 0

    for section in recovery_image_sections_list:
        sections_size += section.header.header_length + section.header.image_length

    if (xml["type"] == RECOVERY_IMAGE_ROT_TYPE):
        pattern = r'^([0-5]{1}[0-9]{1}|6[0-4]{1})\.(\d{2})\.(\d{2})$'
        matches = re.match(pattern, xml["version_id"].decode())
        svn = int(matches.group(1))
        major = int(matches.group(2))
        minor = int(matches.group(3))
        rot_version_instance = rot_version_struct(svn, major, minor)
        version_id_buf = (ctypes.c_ubyte * 32)()
        version_len = ctypes.sizeof(rot_version_instance)
        ctypes.memset(ctypes.addressof(version_id_buf), 0, ctypes.sizeof(version_id_buf))
        ctypes.memmove(ctypes.addressof(version_id_buf), ctypes.addressof(rot_version_instance), version_len)
    else:
        version_len = len(xml["version_id"])
        xml["version_id"] = xml["version_id"].decode() + ''.join('\x00' for i in range(version_len, 32))
        version_id_str_buf = ctypes.create_string_buffer(xml["version_id"].encode('utf-8'), 32)
        version_id_buf = (ctypes.c_ubyte * 32)()
        ctypes.memmove(ctypes.addressof(version_id_buf), ctypes.addressof(version_id_str_buf), 32)

    xml["platform_id"] = xml["platform_id"].decode() + '\x00'
    platform_id_str_buf = ctypes.create_string_buffer(xml["platform_id"].encode('utf-8'), len(xml["platform_id"]))
    platform_id_buf = (ctypes.c_ubyte * len(xml["platform_id"]))()
    ctypes.memmove(ctypes.addressof(platform_id_buf), ctypes.addressof(platform_id_str_buf),
        len(xml["platform_id"]))

    class complete_header(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header_length', ctypes.c_ushort),
                    ('format', ctypes.c_ushort),
                    ('marker', ctypes.c_uint),
                    ('version_id', ctypes.c_ubyte * 32),
                    ('image_length', ctypes.c_uint),
                    ('sig_length', ctypes.c_uint),
                    ('platform_id_length', ctypes.c_ubyte),
                    ('platform_id', ctypes.c_ubyte * len(xml["platform_id"]))]

    class recovery_image(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('recovery_image_header', ctypes.c_ubyte *
                     recovery_image_header_instance.header_length),
                    ('recovery_sections', ctypes.c_ubyte * sections_size)]

    complete_header_instance = complete_header(recovery_image_header_instance.header_length,
        recovery_image_header_instance.type, recovery_image_header_instance.marker,
        version_id_buf, recovery_image_header_instance.image_length,
        recovery_image_header_instance.sig_length,
        recovery_image_header_instance.platform_id_length, platform_id_buf)

    header_buf = (ctypes.c_ubyte * recovery_image_header_instance.header_length)()
    ctypes.memmove(ctypes.addressof(header_buf), ctypes.addressof(complete_header_instance),
        recovery_image_header_instance.header_length)

    offset = 0
    sections_buf = (ctypes.c_ubyte * sections_size)()

    for section in recovery_image_sections_list:
        ctypes.memmove(ctypes.addressof(sections_buf) + offset, ctypes.addressof(section),
            section.header.header_length + section.header.image_length)
        offset += section.header.header_length + section.header.image_length

    return recovery_image(header_buf, sections_buf)

def write_recovery_image(sign, recovery_image, key, output_file_name, recovery_image_header):
    """
    Write recovery image generated to provided path.

    :param sign: Boolean indicating whether to sign the recovery image or not
    :param recovery_image: Generated recovery image to write
    :param key: Key to use for signing
    :param output_filename: Name to use for output file
    :param recovery_image_header: The recovery image header instance

    """
    recovery_image_length = recovery_image_header.image_length - recovery_image_header.sig_length

    if ctypes.sizeof(recovery_image) > (RECOVERY_IMAGE_MAX_SIZE - recovery_image_header.sig_length):
        raise ValueError("Recovery image is too large - {0}".format(ctypes.sizeof(recovery_image)))

    if ctypes.sizeof(recovery_image) != recovery_image_length:
        raise ValueError("Recovery image doesn't match output size")

    if sign:
        mod_fmt = "%%0%dx" % (key.n.bit_length() // 4)
        modulus = binascii.a2b_hex(mod_fmt % key.n)
        exponent = int(key.e)
        mod_length = len(modulus)
        rsa_pub_key_inst = rsa_pub_key_struct(modulus, mod_length, exponent)
        rsa_pub_key_len = ctypes.sizeof(rsa_pub_key_struct)
        recovery_hash_buf = (ctypes.c_ubyte * ctypes.sizeof(recovery_image))()
        ctypes.memmove(ctypes.addressof(recovery_hash_buf), ctypes.addressof(recovery_image), ctypes.sizeof(recovery_image))
        h = SHA256.new(recovery_hash_buf)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(h)
        signature = (ctypes.c_ubyte * recovery_image_header.sig_length).from_buffer_copy(signature)
        recovery_image_buf = (ctypes.c_char * ((recovery_image_header.image_length) + rsa_pub_key_len))()
        ctypes.memmove(ctypes.byref(recovery_image_buf, recovery_image_length), ctypes.addressof(signature),
            recovery_image_header.sig_length)
        ctypes.memmove(ctypes.byref(recovery_image_buf, recovery_image_header.image_length), ctypes.addressof(rsa_pub_key_inst),
            rsa_pub_key_len)
    else:
        recovery_image_buf = (ctypes.c_char * (recovery_image_length))()

    out_dir = os.path.dirname(os.path.abspath(output_file_name))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(output_file_name, 'wb') as fh:
        ctypes.memmove(ctypes.byref(recovery_image_buf), ctypes.addressof(recovery_image),
            recovery_image_length)
        fh.write(recovery_image_buf)

def load_key(key_size, prv_key_path):
    """
    Load private RSA key to sign the recovery image from the provided path. If no valid key can be
    imported, key size will be what is provided. Otherwise, key size will be size of key imported.

    :param key_size: Provided key_size
    :param prv_key_path: Provided private key path

    :return <Sign image or not> <key_size> <Key to use for signing>
    """

    if prv_key_path:
        try:
            key = RSA.importKey(open(prv_key_path).read())
        except Exception:
            print("Unsigned recovery image will be generated, provided RSA key could not be imported: {0}".format(prv_key_path))
            traceback.print_exc ()
            return False, key_size, None

        return True, int(key.n.bit_length() / 8), key
    else:
        print("No RSA private key provided in config, unsigned recovery image will be generated.")
        return False, key_size, None

#*************************************** Start of Script ***************************************

if len(sys.argv) < 2:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), RECOVERY_IMAGE_CONFIG_FILENAME)
else:
    path = os.path.abspath(sys.argv[1])

config = load_config(path)
key_size = None
prv_key_path = None
input_bin_path = None

if "key_size" in config and config["key_size"]:
    key_size = int(config["key_size"])

if "prv_key_path" in config and config["prv_key_path"]:
    prv_key_path = config["prv_key_path"]

if "input" in config and config["input"]:
    input_bin_path = config["input"]

sign, key_size, key = load_key(key_size, prv_key_path)

sig_len = 0 if key_size is None else key_size

processed_xml = load_and_process_xml(config["xml"])

platform_id_len = len(processed_xml["platform_id"])
header_len = ctypes.sizeof(recovery_image_header) + RECOVERY_IMAGE_MAX_VERSION_ID_SIZE + platform_id_len
image_len = get_recovery_image_len(processed_xml, sig_len)
type_in_xml = processed_xml['type']
recovery_image_header_instance = recovery_image_header(header_len, type_in_xml,
    RECOVERY_IMAGE_MAGIC_NUM, image_len, sig_len, platform_id_len)

recovery_image_sections_list = generate_recovery_image_section_list(processed_xml)
recovery_image = generate_recovery_image(processed_xml, recovery_image_header_instance,
    recovery_image_sections_list)

write_recovery_image(sign, recovery_image, key, config["output"], recovery_image_header_instance)

print("Completed recovery image generation: {0}".format(config["output"]))
