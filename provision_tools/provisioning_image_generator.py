import json
import os
import sys
import configparser
import ctypes
import binascii
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512

PROVISIONING_CONFIG_FILENAME = "provisioning_image_generator.ini"
IMAGE_TYPE = int("0x02", 16)
MAGIC_NUM = int("0x8A147C29", 16)
RESERVED_VALUE = int("0x0000", 16)
PROVISION_OTP = False

RSA2048_SIG_LEN = 256
RSA3072_SIG_LEN = 384
RSA4096_SIG_LEN = 512
RSA_MAX_SIG_LEN = RSA4096_SIG_LEN


class provision_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('image_length', ctypes.c_ushort),
                ('image_type', ctypes.c_ushort),
                ('magic_num', ctypes.c_int)]


class manifest_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('manifest_length', ctypes.c_ushort),
                ('flag', ctypes.c_int),
                ('Reserved', ctypes.c_ushort)]


class provision_data(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('header', manifest_header),
                ('BMCPFMOffset', ctypes.c_int),
                ('BMCActiveSize', ctypes.c_int),
                ('BMCRecoveryOffset', ctypes.c_int),
                ('BMCRecoverySize', ctypes.c_int),
                ('BMCStagingOffset', ctypes.c_int),
                ('BMCStageSize', ctypes.c_int),
                ('PCHPFMOffset', ctypes.c_int),
                ('PCHActiveSize', ctypes.c_int),
                ('PCHRecoveryOffset', ctypes.c_int),
                ('PCHRecoverySize', ctypes.c_int),
                ('PCHStagingOffset', ctypes.c_int),
                ('PCHStageSize', ctypes.c_int)]


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


def validate_json_content(json_data):
    global PROVISION_OTP
    retval = True

    for keys in json_data:
        if keys == "Flag" and ((json_data["Flag"] == "0x0F") or
                               (json_data["Flag"] == "0x01")):
            if (json_data["Flag"] == "0x0F"):
                PROVISION_OTP = True
                if ('OTPKey' not in json_data) or ('OTP_Image' not in json_data):
                    print("Make sure the key '{}' is provided in Json file... ".format(keys))
                    retval = False
                    break
                else:
                    if (json_data.get('OTPKey') == "") or (json_data.get('OTP_Image') == ""):
                        print("Make sure the value of the key '{}' is provided in Json file... ".format(keys))
                        retval = False
                        break
        elif (keys.find("Offset") != -1) or (keys.find("Size") != -1):
            if (len(json_data.get(keys)[2:]) != 8):
                retval = False
                print("Make sure length of the key '{}' in Json file is 4 bytes... ".format(keys))
                break
        elif (keys.find("Key") != -1):
            if not os.path.isfile(json_data.get(keys)):
                retval = False
                print("Provided key '{}' having the file '{}' is not in the specified location... ".format(keys, json_data.get(keys)))
                break
        elif (keys == 'OTP_Image'):
            continue
        else:
            print("Provided json content is not correct. Either it is an invalid key or value in JSON File. The error occurs in the key: '{}' ".format(keys))
            retval = False
            break

    return retval


def read_input_jsonfile(input_json_path):
    provisioning_data = provision_data()
    provisioning_data_length = 0
    json_data = {}
    retval = True

    try:
        if (os.path.isfile(input_json_path)):
            jsonfile = input_json_path.split(".")  # splitting the json file path to list of values
            if(jsonfile[1].lower() == "json"):  # checking entered file path contains json file or not
                print("Entered input path contains json file...")
                with open(input_json_path, "r") as f:
                    file_data = f.read()
                    json_data = json.loads(file_data)
                    valid = validate_json_content(json_data)
                    if valid:
                        Flag = int(json_data["Flag"], 16)
                        BMCPFMOffset = int(json_data["BMCPFMOffset"], 16)
                        BMCActiveSize = int(json_data["BMCActiveSize"], 16)
                        BMCRecoveryOffset = int(json_data["BMCRecoveryOffset"], 16)
                        BMCRecoverySize = int(json_data["BMCRecoverySize"], 16)
                        BMCStagingOffset = int(json_data["BMCStagingOffset"], 16)
                        BMCStageSize = int(json_data["BMCStageSize"], 16)
                        PCHPFMOffset = int(json_data["PCHPFMOffset"], 16)
                        PCHActiveSize = int(json_data["PCHActiveSize"], 16)
                        PCHRecoveryOffset = int(json_data["PCHRecoveryOffset"], 16)
                        PCHRecoverySize = int(json_data["PCHRecoverySize"], 16)
                        PCHStagingOffset = int(json_data["PCHStagingOffset"], 16)
                        PCHStageSize = int(json_data["PCHStageSize"], 16)
                        manifest_header_instance = manifest_header(0, Flag, RESERVED_VALUE)
                        provisioning_data = provision_data(manifest_header_instance,
                                                           BMCPFMOffset,
                                                           BMCActiveSize,
                                                           BMCRecoveryOffset,
                                                           BMCRecoverySize,
                                                           BMCStagingOffset,
                                                           BMCStageSize,
                                                           PCHPFMOffset,
                                                           PCHActiveSize,
                                                           PCHRecoveryOffset,
                                                           PCHRecoverySize,
                                                           PCHStagingOffset,
                                                           PCHStageSize)
                        provisioning_data_length = ctypes.sizeof(provisioning_data)
                    else:
                        retval = False
            else:
                print("Entered file : " + input_json_path + " is not a Json file...")
                retval = False
        else:
            print("Make sure Json file : " + input_json_path + " is present in as per configuration file...")
            retval = False
    except Exception as msg:
        print("Error:", msg)
        retval = False

    return retval, provisioning_data, provisioning_data_length, json_data


def read_config_file(input_config_path):
    config_data = {}
    retval = True

    try:
        if (os.path.isfile(input_config_path)):
            config = configparser.ConfigParser()
            config.read(input_config_path)
            config_data["input_json_path"] = config.get("input section", "input_json")
            key_type = config.get("input section", "key_type")
            if key_type == "ECC":
                config_data["key_type"] = 1
            if key_type == "RSA":
                config_data["key_type"] = 0
            config_data["output_file"] = config.get("input section", "output_file")
            if "key_size" in config["input section"]:
                config_data["key_size"] = config.get("input section", "key_size")
        else:
            print("Unable to find config file " + input_config_path + " make sure that it is present in the tool location...")
            retval = False
    except Exception as msg:
        print("Error:", msg)
        retval = False

    return retval, config_data


def load_key(key_type, prv_key_path):
    if prv_key_path:
        try:
            key = None
            if key_type == 1:
                key = ECC.import_key(open(prv_key_path).read())
                keysize = int(key.pointQ.size_in_bytes())
            else:
                key = RSA.importKey(open(prv_key_path).read())
                keysize = int(key.n.bit_length() / 8)

        except Exception as err:
            raise IOError("Provided {0} key could not be imported: {1} - Error: {2}".format(
                "ECC" if key_type == 1 else "RSA", prv_key_path, err))

        return True, keysize, key
    else:
        print("No RSA private key provided in config, unsigned manifest will be generated.")
        return False, None, None


def generate_root_public_key(key_type, public_key_file):
    pubkey = b""
    retval = True

    try:
        key_load, key_size, key = load_key(key_type, public_key_file)
        if key_load:
            if key_type == 0:
                mod_fmt = "%%0%dx" % (key.n.bit_length() // 4)
                modulus = binascii.a2b_hex(mod_fmt % key.n)
                exponent = int(key.e)
                mod_length = len(modulus)
                rsa_pub_key_inst = rsa_pub_key_struct(modulus, mod_length, exponent)
                pubkey = bytearray(rsa_pub_key_inst)
                # print(binascii.hexlify(pubkey))
            else:
                pubkey = b""
        else:
            print("Failed to load the key..")
            retval = False
    except Exception as err:
        print("Error in creating the public key: ", err)
        retval = False

    return retval, pubkey


def main():
    input_config_path = None
    input_json_path = None

    if len(sys.argv) < 2:
        input_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), PROVISIONING_CONFIG_FILENAME)
    else:
        input_config_path = os.path.abspath(sys.argv[1])

    isconfig, config_data = read_config_file(input_config_path)

    if isconfig:
        provision_header_instance = provision_header(0, IMAGE_TYPE, MAGIC_NUM)
        isjson, provisioning_data, provisioning_data_length, json_data = read_input_jsonfile(config_data["input_json_path"])
    else:
        print("Error in reading the Config File. Provisioning Image has not been generated")

    key_type = config_data["key_type"]
    sig_length = int(config_data["key_size"], 10)
    output_file = config_data["output_file"]

    if isjson:
        retval, public_key = generate_root_public_key(key_type, json_data["RootKey"])
        if PROVISION_OTP is True:
            retval, otp_public_key = generate_root_public_key(key_type, json_data["OTPKey"])

        if retval:
            provisioning_data.header.manifest_length = manifest_length = provisioning_data_length + len(public_key)
            provision_header_instance.image_length = provisioning_data_length + len(public_key) + sig_length + ctypes.sizeof(provision_header)
            if PROVISION_OTP is True:
                provisioning_data.header.manifest_length = manifest_length = provisioning_data.header.manifest_length + len(otp_public_key)
                provision_header_instance.image_length = provision_header_instance.image_length + len(otp_public_key)

            data_length = manifest_length + ctypes.sizeof(provision_header)
            manifest_hash_buf = (ctypes.c_ubyte * data_length)()
            public_key_bytes = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
            if PROVISION_OTP is True:
                otp_public_key_bytes = (ctypes.c_ubyte * len(otp_public_key)).from_buffer_copy(otp_public_key)

            ctypes.memmove(ctypes.addressof(manifest_hash_buf),
                           ctypes.addressof(provision_header_instance),
                           ctypes.sizeof(provision_header_instance))

            ctypes.memmove(ctypes.byref(manifest_hash_buf, ctypes.sizeof(provision_header_instance)),
                           ctypes.addressof(provisioning_data),
                           ctypes.sizeof(provisioning_data))

            ctypes.memmove(ctypes.byref(manifest_hash_buf, data_length - (2 * len(public_key) if PROVISION_OTP is True else len(public_key))), public_key_bytes, len(public_key))

            if PROVISION_OTP is True:
                ctypes.memmove(ctypes.byref(manifest_hash_buf, data_length - len(otp_public_key)), otp_public_key_bytes, len(otp_public_key))

            key_load, key_size, key = load_key(key_type, json_data["OTPSignKey"])
            sha_algo = SHA512 if key_size == 512 else SHA384 if key_size == 384 else SHA256
            h = sha_algo.new(manifest_hash_buf)

            if key_type == 1:
                signer = DSS.new(key, 'fips-186-3', 'der')
            else:
                signer = PKCS1_v1_5.new(key)

            signature = signer.sign(h)
            signature_buf_len = len(signature) if len(signature) < sig_length else sig_length
            signature_buf = (ctypes.c_ubyte * signature_buf_len).from_buffer_copy(signature)
            manifest_buf = (ctypes.c_char * (data_length + sig_length))()
            ctypes.memset(manifest_buf, 0, data_length + sig_length)
            ctypes.memmove(ctypes.byref(manifest_buf, data_length), ctypes.addressof(signature_buf), signature_buf_len)
            ctypes.memmove(ctypes.byref(manifest_buf), ctypes.addressof(manifest_hash_buf), data_length)

            with open(output_file, 'wb+') as fh:
                fh.write(manifest_buf)
            print("Provisioning Image has been generated")
        else:
            print("Failed to generate the public key. Provisioning Image has not been generated")
    else:
        print("Error in reading the JSON File. Provisioning Image has not been generated")


if __name__ == '__main__':
    main()
