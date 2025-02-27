#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

"""Modules imported for unpack tool"""
import argparse
from datetime import datetime
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
import uuid

UNPACK_TOOL_VERSION = "4.1.3"

class Util:
    """
    Class with static helper functions
    """
    LOG_FILE = "./fwpkg_unpack_log.txt"
    LOGFILE_PATH = ""

    @staticmethod
    def cli_log(log_msg, log_file_only=False):
        """
        Append log message to cli log file
        """
        log_file = Util.LOG_FILE

        file_handle = None
        try:
            with open(log_file, "a+", encoding="utf-8") as file_handle:
                localtime = time.asctime(time.localtime(time.time()))
                file_handle.write(f"{localtime} : {log_msg}\n")
                Util.LOGFILE_PATH = os.path.abspath(file_handle.name)
            if log_file_only is False:
                print(log_msg)
        except PermissionError as _:
            print(log_msg)
            print(f"Error: Failed to open or create {log_file}")

    @staticmethod
    def get_descriptor_type_name(desc_type):
        """
        Return the descriptive name for given integer descriptor type.
        """
        desc_type_dict = {
            0x0000: "PCI Vendor ID",
            0x0001: "IANA Enterprise ID",
            0x0002: "UUID",
            0x0003: "PnP Vendor ID",
            0x0004: "ACPI Vendor ID",
            0x0005: "IEEE Assigned Company ID",
            0x0006: "SCSI Vendor ID",
            0x0100: "PCI Device ID",
            0x0101: "PCI Subsystem Vendor ID",
            0x0102: "PCI Subsystem ID",
            0x0103: "PCI Revision ID",
            0x0104: "PnP Product Identifier",
            0x0105: "ACPI Product Identifier",
            0x0106: "ASCII Model Number",
            0x0107: "ASCII Model Number",
            0x0108: "SCSI Product ID",
            0x0109: "UBM Controller Device Code",
            0xffff: "Vendor Defined",
        }

        name = desc_type_dict.get(desc_type, f'{desc_type:#x}')
        return name

    @staticmethod
    def get_alt_time_format(time_stamp):
        """ Convert Y-m-d H:M:S:f z format to d/m/y H:M:S """
        parts = time_stamp.split(' ')
        time_stamp_no_zone = ' '.join(parts[:-1])
        original_format = "%Y-%m-%d %H:%M:%S:%f"
        date_object = datetime.strptime(time_stamp_no_zone, original_format)
        new_format = "%d/%m/%Y %H:%M:%S"
        new_time_stamp = date_object.strftime(new_format)
        return new_time_stamp

    @staticmethod
    def get_set_bit_indices(int_val):
        """ Get list of set bit indices in a number """
        set_bit_indices = []
        index = 0
        while int_val > 0:
            if int_val & 1:
                set_bit_indices.append(index)
            int_val >>= 1
            index += 1
        return set_bit_indices

    @staticmethod
    def get_timestamp_str(timestamp):
        """
        Return timestamp string from 13 byte binary data
        according to PLDM Base specification
        """
        year = timestamp[11]
        year = year << 8
        year = year | timestamp[10]
        time_str = str(year) + "-"
        time_str = time_str + str(timestamp[9])
        time_str = time_str + "-" + str(timestamp[8])
        time_str = time_str + " " + str(timestamp[7])
        time_str = time_str + ":" + str(timestamp[6])
        time_str = time_str + ":" + str(timestamp[5])
        micro_sec = timestamp[4]
        micro_sec = micro_sec << 8
        micro_sec = micro_sec | timestamp[3]
        micro_sec = micro_sec << 8
        micro_sec = micro_sec | timestamp[2]
        time_str = time_str + ":" + str(micro_sec)
        utc_offset = timestamp[1]
        utc_offset = utc_offset << 8
        utc_offset = utc_offset | timestamp[0]
        sign = "+"
        if utc_offset < 0:
            utc_offset = utc_offset * -1
            sign = "-"
        time_str = time_str + " " + sign + str(utc_offset)
        return time_str

    @staticmethod
    def get_checksum_for_component_image(fw_image):
        """
        Compute SHA256 for the given component image.
        """
        sha256 = ""
        try:
            with open(fw_image, 'rb') as file_name:
                data = file_name.read()
                sha256 = hashlib.sha256(data).hexdigest()
        except (FileNotFoundError, IOError) as err:
            log_msg = f'Error: {err}'
            Util.cli_log(log_msg, False)
        return sha256

    @staticmethod
    def get_padded_hex(byte_arr):
        """
        Get hex formatted version of a byte array padded with 0
        """
        total_len = len(byte_arr)
        hex_str = hex(
            int.from_bytes(byte_arr, byteorder='little', signed=False))[2:]
        padded_str = '0x' + hex_str.zfill(total_len * 2)
        return padded_str


class PLDMUnpack:
    # pylint: disable=too-many-instance-attributes
    """
    PLDMUnpack class implements a PLDM parser and the unpack tool
    along with its required features.
    ...
    Attributes
    ----------
    package : str
        Path/Name of the input firmware package
    unpack : bool
        True if tool should unpack firmware images
    fwpkg_fd : io.TextIOWrapper
        Instance used to read from package file
    header_map : dict
        Stores the PLDM Package Header Information parsed from given package
    device_id_record_count : int
        Number of PLDM FirmwareDeviceIDRecords found in given package
    fd_id_record_list : list
        List of FirmwareDeviceIDRecords parsed from given package
    component_img_info_list : list
        List of ComponentImageInformation parsed from given package

    Methods
    -------
    parse_header() :
        Parses PLDM Package Header Information
    parse_device_id_records() :
        Parses FirmwareDeviceIDRecords from package
    parse_component_img_info() :
        Parses ComponentImageInformation from package
    get_image_name_from_records(comp_info_index) :
        Identify records which which contain metadata for image naming
    get_image_name(comp_info_index) :
        Get image name string by appending various metadata
    create_unpacked_files(output_dir) :
        Extract each firmware image in a file
    unpack_pldm_package(package_name, output_dir) :
        Perform complete parsing and extraction of package
    get_applicable_component_index(applicable_component):
        Return applicable_component as list of indices
    get_ec_info(filepath) :
        Get all EC metadata from extraxted firmware
    get_ap_metadata(filepath) :
        Get all AP metadata from extraxted firmware
    get_signature_type(fw_image, component_identifier):
        Get Signature type for given firmware image and component identifier
    is_glacier_device(product, device_name):
        Is this device a glacer device
    get_formatted_descriptors(record_desc, components):
        Method to prepare descriptor section for json output
    prepare_records_json():
        Prepares the JSON output.

    """
    def __init__(self):
        """
        Contructor for PLDMUnpack class
        """
        self.unpack = True
        self.package = ""
        self.fwpkg_fd = 0
        self.header_map = {}
        self.device_id_record_count = 0
        self.fd_id_record_list = []
        self.component_img_info_list = []
        self.full_header = {
            "PackageHeaderInformation": {},
            "FirmwareDeviceIdentificationArea": {},
            "ComponentImageInformationArea": {},
            "Package Header Checksum": ''
        }
        self.pkg_builder_json = {
            "PackageHeaderInformation":{},
            "FirmwareDeviceIdentificationArea": [],
            "ComponentImageInformationArea": []
        }
        self.verbose = False
        self.little_endian_list = [
            "IANA Enterprise ID", "PCI Vendor ID", "PCI Device ID",
            "PCI Subsystem Vendor ID", "PCI Subsystem ID"
        ]

    def parse_header(self):
        """
        Parse PLDM header data into self.header_map
        Returns :
            True if parsing successful
        """
        # check if UUID is valid
        pldm_fw_header_id_v1_0 = b'\xf0\x18\x87\x8c\xcb\x7d\x49\x43\x98\x00\xa0\x2f\x05\x9a\xca\x02'
        uuid_v1_0 = str(uuid.UUID(bytes=pldm_fw_header_id_v1_0))
        try:
            self.header_map["PackageHeaderIdentifier"] = str(
            uuid.UUID(bytes=self.fwpkg_fd.read(16)))
        except ValueError:
            log_msg = "Error: incorrect package format."
            Util.cli_log(log_msg, False)
            return False

        if uuid_v1_0 != self.header_map["PackageHeaderIdentifier"]:
            log_msg = "Expected PLDM v1.0 but PackageHeaderIdentifier is "\
            + self.header_map["PackageHeaderIdentifier"]
            Util.cli_log(log_msg, False)
            return False
        self.header_map["PackageHeaderFormatRevision"] = str(
            int.from_bytes(self.fwpkg_fd.read(1),
                           byteorder='little',
                           signed=False))
        self.header_map["PackageHeaderSize"] = int.from_bytes(
            self.fwpkg_fd.read(2), byteorder='little', signed=False)
        timestamp = self.fwpkg_fd.read(13)
        self.header_map["PackageReleaseDateTime"] = Util.get_timestamp_str(
            timestamp)
        self.header_map["ComponentBitmapBitLength"] = int.from_bytes(
            self.fwpkg_fd.read(2), byteorder='little', signed=False)
        self.header_map["PackageVersionStringType"] = int.from_bytes(
            self.fwpkg_fd.read(1), byteorder='little', signed=False)
        version_str_len = int.from_bytes(self.fwpkg_fd.read(1),
                                         byteorder='little',
                                         signed=False)
        self.header_map["PackageVersionStringLength"] = version_str_len
        self.header_map["PackageVersionString"] = self.fwpkg_fd.read(
            version_str_len).split(b'\x00')[0].decode('utf-8')
        self.full_header["PackageHeaderInformation"] = self.header_map
        return True

    def parse_device_id_records(self):
        """
        Parse PLDM FirmwareDeviceIDRecords data into self.fd_id_record_list
        Returns:
            True if parsing is successful
        """
        # pylint: disable=line-too-long
        self.device_id_record_count = int.from_bytes(self.fwpkg_fd.read(1),
                                                     byteorder='little',
                                                     signed=False)
        for _ in range(self.device_id_record_count):
            id_record_map = {}
            id_record_map["RecordLength"] = int.from_bytes(
                self.fwpkg_fd.read(2), byteorder='little', signed=False)
            id_record_map["DescriptorCount"] = int.from_bytes(
                self.fwpkg_fd.read(1), byteorder='little', signed=False)
            id_record_map["DeviceUpdateOptionFlags"] = int.from_bytes(
                self.fwpkg_fd.read(4), byteorder='little', signed=False)
            id_record_map[
                "ComponentImageSetVersionStringType"] = int.from_bytes(
                    self.fwpkg_fd.read(1), byteorder='little', signed=False)
            id_record_map[
                "ComponentImageSetVersionStringLength"] = int.from_bytes(
                    self.fwpkg_fd.read(1), byteorder='little', signed=False)
            id_record_map["FirmwareDevicePackageDataLength"] = int.from_bytes(
                self.fwpkg_fd.read(2), byteorder='little', signed=False)
            applicable_component_size = math.ceil(
                self.header_map["ComponentBitmapBitLength"] / 8)
            id_record_map["ApplicableComponents"] = int.from_bytes(
                self.fwpkg_fd.read(applicable_component_size),
                byteorder='little',
                signed=False)
            id_record_map[
                "ComponentImageSetVersionString"] = self.fwpkg_fd.read(
                    id_record_map["ComponentImageSetVersionStringLength"]
                ).split(b'\x00')[0].decode('utf-8')
            descriptors = []
            for j in range(id_record_map["DescriptorCount"]):
                descriptor_map = {}
                if j == 0:
                    descriptor_map["InitialDescriptorType"] = int.from_bytes(
                        self.fwpkg_fd.read(2),
                        byteorder='little',
                        signed=False)
                    descriptor_map["InitialDescriptorLength"] = int.from_bytes(
                        self.fwpkg_fd.read(2),
                        byteorder='little',
                        signed=False)
                    value = self.fwpkg_fd.read(
                        descriptor_map["InitialDescriptorLength"])
                    descriptor_map["InitialDescriptorData"] = value

                else:
                    descriptor_map[
                        "AdditionalDescriptorType"] = int.from_bytes(
                            self.fwpkg_fd.read(2),
                            byteorder='little',
                            signed=False)
                    descriptor_map[
                        "AdditionalDescriptorLength"] = int.from_bytes(
                            self.fwpkg_fd.read(2),
                            byteorder='little',
                            signed=False)
                    if descriptor_map["AdditionalDescriptorType"] == 0xFFFF:
                        descriptor_map[
                            "VendorDefinedDescriptorTitleStringType"] = int.from_bytes(
                                self.fwpkg_fd.read(1),
                                byteorder='little',
                                signed=False)
                        descriptor_map[
                            "VendorDefinedDescriptorTitleStringLength"] = int.from_bytes(
                                self.fwpkg_fd.read(1),
                                byteorder='little',
                                signed=False)
                        descriptor_map[
                            "VendorDefinedDescriptorTitleString"] = self.fwpkg_fd.read(
                                descriptor_map[
                                    "VendorDefinedDescriptorTitleStringLength"]
                            ).split(b'\x00')[0].decode('utf-8')
                        vendor_def_data_len = (
                            descriptor_map["AdditionalDescriptorLength"] -
                            (2 + descriptor_map[
                                "VendorDefinedDescriptorTitleStringLength"]))
                        descriptor_map[
                            "VendorDefinedDescriptorData"] = self.fwpkg_fd.read(
                                vendor_def_data_len).hex()
                    else:
                        descriptor_map[
                            "AdditionalDescriptorIdentifierData"] = self.fwpkg_fd.read(
                                descriptor_map["AdditionalDescriptorLength"])
                descriptors.append(descriptor_map)
            id_record_map["RecordDescriptors"] = descriptors
            id_record_map["FirmwareDevicePackageData"] = self.fwpkg_fd.read(
                id_record_map["FirmwareDevicePackageDataLength"]).decode(
                    'utf-8')
            self.fd_id_record_list.append(id_record_map)
        self.full_header["FirmwareDeviceIdentificationArea"] = {
            "DeviceIDRecordCount": self.device_id_record_count,
            "FirmwareDeviceIDRecords": self.fd_id_record_list
        }
        return True

    def parse_component_img_info(self):
        """
        Parse PLDM Component Image info data into self.fd_id_record_list
        Returns :
            True if parsing successful
        """
        component_image_count = int.from_bytes(self.fwpkg_fd.read(2),
                                               byteorder='little',
                                               signed=False)
        for _ in range(component_image_count):
            comp_info = {}
            comp_info["ComponentClassification"] = int.from_bytes(
                self.fwpkg_fd.read(2), byteorder='little', signed=False)
            comp_info["ComponentIdentifier"] = hex(
                int.from_bytes(self.fwpkg_fd.read(2),
                               byteorder='little',
                               signed=False))
            comp_info["ComponentComparisonStamp"] = Util.get_padded_hex(self.fwpkg_fd.read(4))
            comp_info["ComponentOptions"] = int.from_bytes(
                self.fwpkg_fd.read(2), byteorder='little', signed=False)
            comp_info["RequestedComponentActivationMethod"] = int.from_bytes(
                self.fwpkg_fd.read(2), byteorder='little', signed=False)
            # RequestedComponentActivationMethod can have any combination of bits 0:5 set
            # Any value above 0x3F is invalid
            activation_val = comp_info["RequestedComponentActivationMethod"]
            if activation_val > 0x3F:
                Util.cli_log(
                    f"Found invalid value for RequestedComponentActivationMethod={activation_val}",
                    True)
            comp_info["ComponentLocationOffset"] = int.from_bytes(
                self.fwpkg_fd.read(4), byteorder='little', signed=False)
            comp_info["ComponentSize"] = int.from_bytes(self.fwpkg_fd.read(4),
                                                        byteorder='little',
                                                        signed=False)
            comp_info["ComponentVersionStringType"] = int.from_bytes(
                self.fwpkg_fd.read(1), byteorder='little', signed=False)
            comp_info["ComponentVersionStringLength"] = int.from_bytes(
                self.fwpkg_fd.read(1), byteorder='little', signed=False)
            comp_info["ComponentVersionString"] = self.fwpkg_fd.read(
                comp_info["ComponentVersionStringLength"]).split(b'\x00')[0].decode('utf-8')
            self.component_img_info_list.append(comp_info)
        self.full_header["ComponentImageInformationArea"] = {
            "ComponentImageCount": component_image_count,
            "ComponentImageInformation": self.component_img_info_list
        }
        return True

    def get_image_name_from_records(self, comp_info_index):
        """
        Identify records which which contain metadata for image at
        index comp_info_index component image info list
        Parameter:
            comp_info_index index of image in component image
            info section
        Returns:
            Name of the applicable record for given image
            or "" if nothing found
        """
        mask = 1 << comp_info_index
        for rec in self.fd_id_record_list:
            applicable_comp_indices = rec["ApplicableComponents"]
            name = rec["ComponentImageSetVersionString"]
            if mask & applicable_comp_indices == mask:
                if name.find(",") == -1:
                    return name, rec['RecordDescriptors']
                components = name.split(",")
                applicable_comp = applicable_comp_indices
                count = 0
                for _ in range(comp_info_index + 1):
                    if applicable_comp & 1 == 1:
                        count = count + 1
                    applicable_comp = applicable_comp >> 1
                return components[count - 1], rec['RecordDescriptors']
        return "", None

    def get_image_name(self, comp_info_index):
        """
        Create the image name string by appending various metadata
        separated by '_'
        Parameter:
            comp_info_index index of image in component image
            for naming
        Returns:
            Name of the image for unpacking
            or ""
        """
        comp_info = self.component_img_info_list[comp_info_index]
        name, _ = self.get_image_name_from_records(comp_info_index)
        if name != "":
            name = name.replace(":", "_")
            name = name.replace("_N/A", "")
            name = name + "_" + comp_info["ComponentVersionString"]
            if name.startswith("FW-Package"):
                name = name + ".fwpkg"
            else:
                name = name + "_image.bin"
            name = re.sub("_+", "_", name)
        return name

    def create_unpacked_files(self, output_dir):
        """
        Extract each firmware image from the
        Firmware Package Payload section of the input file.
        Parameter:
            output_dir path of the directory to store the
            extracted files
        Returns:
            True if unpacking was successful
        """
        # pylint: disable=too-many-locals
        package_size = os.path.getsize(self.package)
        for index, info in enumerate(self.component_img_info_list):
            offset = info["ComponentLocationOffset"]
            size = info["ComponentSize"]
            if offset + size > package_size:
                log_msg = f"Error: ComponentLocationOffset {offset} + \
                ComponentSize {size} exceeds given package size {package_size}"

                Util.cli_log(log_msg, False)
                return False
            img_name = output_dir + self.get_image_name(index)
            img_name = re.sub(r'\s+', '', img_name)
            if img_name == "":
                log_msg = "Error: The input firmware package does not conform to \
                the format created by NVIDIA packaging tool."

                Util.cli_log(log_msg, False)
                return False
            try:
                if os.path.exists(img_name):
                    os.remove(img_name)
                with open(img_name, "w+b") as component_img_fd:
                    self.fwpkg_fd.seek(offset, 0)
                    bytes_left = size
                    buffer_size = 2048
                    while bytes_left > 0:
                        if bytes_left < 2048:
                            buffer_size = bytes_left
                        buffer = self.fwpkg_fd.read(buffer_size)
                        component_img_fd.write(buffer)
                        bytes_left = bytes_left - buffer_size
                    info["FWImageName"] = img_name
                if os.path.exists(img_name):
                    os.chmod(img_name,
                             stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                    if img_name.endswith('_image.bin'):
                        sha256_hash = Util.get_checksum_for_component_image(
                            img_name)[:8]
                        base, _ = img_name.rsplit('_image.bin', 1)
                        new_img_name = base + "_" + sha256_hash + "_image.bin"
                        os.rename(img_name, new_img_name)
                        info["FWImageName"] = new_img_name
            except OSError as err:
                log_msg = f"Error: Could not create file {img_name} due to {err}"
                Util.cli_log(log_msg, False)
                return False
        return True

    def get_pldm_header_checksum(self):
        """ Read PLDM header checksum """
        self.full_header['Package Header Checksum'] = int.from_bytes(
            self.fwpkg_fd.read(4), byteorder='little', signed=False)

    def unpack_pldm_package(self, package_name, output_dir):
        """
        Parse the PLDM package and get information about components included in the FW image.
        Unpack the package if required.
        Parameters:
            package_name filepath of input package file
            output_dir directory to store the resulting unpacked files
        Returns:
            True if parsing and unpacking was successful
        """
        if package_name == "" or package_name is None:
            log_msg = "ERROR: Firmware package file is mandatory."
            Util.cli_log(log_msg, False)
            return False
        if os.path.exists(package_name) is False:
            log_msg = print("ERROR: File does not exist at path ",
                            package_name)
            Util.cli_log(log_msg, False)
            return False
        self.package = package_name
        try:
            with open(self.package, "rb") as self.fwpkg_fd:
                parsing_valid = self.parse_header()
                if parsing_valid:
                    parsing_valid = self.parse_device_id_records()
                    if parsing_valid:
                        parsing_valid = self.parse_component_img_info()
                        self.get_pldm_header_checksum()
                if parsing_valid and self.unpack:
                    if output_dir == "" or output_dir is None:
                        # If outdir was not given in command
                        # assume current directory
                        output_dir = "."
                    output_dir = os.path.abspath(output_dir) + "/"
                    # If dir doesn't exist, create it
                    if os.path.isdir(output_dir) is False:
                        os.makedirs(output_dir)
                    parsing_valid = self.create_unpacked_files(output_dir)
                if self.verbose:
                    log_message = f"PLDM Output directory: {output_dir}," \
                        f"Package name: {package_name}"

                    Util.cli_log(log_message, True)
                    if parsing_valid is False:
                        log_message = f"Package Header Contents: {str(self.header_map)}"
                        Util.cli_log(log_message, True)
                        log_message = f"FirmwareDeviceIDRecords Contents: \
                            {str(self.fd_id_record_list)}"
                        Util.cli_log(log_message, True)
                        log_message = f"ComponentImageInformation Contents:\
                            {str(self.component_img_info_list)}"
                        Util.cli_log(log_message, True)
            return parsing_valid
        except IOError as e_io_error:
            log_message = f"Couldn't open or read given FW package ({e_io_error})"
            Util.cli_log(log_message, False)
            return False

    def get_applicable_component_index(self, applicable_component):
        """
        Return list of indices of applicable component images from
        applicable_component index bitmap.
        """
        # number of images in the image section
        max_bits = len(self.component_img_info_list)
        indices = []
        for shift in range(max_bits):
            # for each index check if the bit at that position is set in applicable_component
            mask = 1 << shift
            result = applicable_component & mask
            if result == mask:
                indices.append(shift)
        return indices

    # pylint: disable=unused-argument
    def get_signature_type(self, fw_image, component_identifier):
        """ Method to tell if unpacked bin is prod signed or debug signed """
        return 'N/A'

    @staticmethod
    def is_glacier_device(record, device_name):
        """
        Is this device a glacer device
        """
        if device_name.startswith("ERoT"):
            return True
        if record["DescriptorCount"] == 0:
            return False
        record_desc = record["RecordDescriptors"]
        for desc in record_desc:
            descriptor_type = desc.get("AdditionalDescriptorType", "")
            if descriptor_type == 65535:
                title = desc.get("VendorDefinedDescriptorTitleString", "")
                if title == "GLACIERDSD":
                    return True
        return False

    def get_applicable_components_names(self, record):
        # pylint: disable=too-many-branches
        """
        Method to create list of applicable component images and their metadata like
        ComponentIdentifier and Version. FWImage is included if unpacking was done.
        Also prepares ComponentImageSetVersionString in name:model:vendor,... format if
        it is not already so.
        """
        index = self.get_applicable_component_index(
            record["ApplicableComponents"])
        components = []
        device_name = record["ComponentImageSetVersionString"]
        for i in index:
            component = {}
            img = self.component_img_info_list[i]
            if self.unpack is True:
                component = {
                    "ComponentIdentifier": "",
                    "ComponentVersionString": "",
                    "FWImage": ""
                }
                component["FWImage"] = img["FWImageName"]
                component[
                    "FWImageSHA256"] = Util.get_checksum_for_component_image(
                        component["FWImage"])
                # For ERoT associated devices get signature type
                if self.is_glacier_device(
                        record, component["FWImage"].rsplit('/', 1)[-1]):
                    signature_type = self.get_signature_type(
                        component["FWImage"], img["ComponentIdentifier"])
                    if signature_type:
                        component["SignatureType"] = signature_type
                else:
                    component["SignatureType"] = "N/A"
                component["FWImageSize"] = img["ComponentSize"]
            else:
                component = {
                    "ComponentIdentifier": "",
                    "ComponentVersionString": ""
                }
            component["ComponentIdentifier"] = img["ComponentIdentifier"]
            component["ComponentVersionString"] = img["ComponentVersionString"]
            components.append(component)
        if not self.unpack:
            ap_sku, ec_sku = 'N/A', 'N/A'
            records = record["RecordDescriptors"]
            for i in range(1, len(records)):
                if records[i]["AdditionalDescriptorType"] == 65535:
                    if records[i][
                            "VendorDefinedDescriptorTitleString"] == "APSKU":
                        ap_sku = "0x" + records[i][
                            "VendorDefinedDescriptorData"]
                    elif records[i][
                            "VendorDefinedDescriptorTitleString"] == "ECSKU":
                        ec_sku = "0x" + records[i][
                            "VendorDefinedDescriptorData"]

            for component in components:
                if component.get("ComponentIdentifier") == "0xff00":
                    component["ECSKUID"] = ec_sku
                else:
                    component["APSKUID"] = ap_sku
        return components, device_name

    def decode_descriptor_data(self, desc_type_name, desc_data):
        """ Formatting for descriptor data based on endianess"""
        desc_val = ""
        if desc_type_name in self.little_endian_list:
            desc_val = Util.get_padded_hex(desc_data)
        else:
            desc_val = "0x" + desc_data.hex()
        return desc_val

    def get_formatted_descriptors(self, record_desc, components):
        """
        Method to prepare stripped and formatted descriptor section for json output.
        """
        records = record_desc["RecordDescriptors"]
        descriptors = []
        desc = {}
        if len(records) == 0:
            return descriptors
        desc["InitialDescriptorType"] = Util.get_descriptor_type_name(
            records[0]["InitialDescriptorType"])
        desc["InitialDescriptorData"] = self.decode_descriptor_data(
            desc["InitialDescriptorType"], records[0]["InitialDescriptorData"])
        descriptors.append(desc)
        for i in range(1, len(records)):
            desc = {}
            desc["AdditionalDescriptorType"] = Util.get_descriptor_type_name(
                records[i]["AdditionalDescriptorType"])
            if records[i]["AdditionalDescriptorType"] == 65535:
                desc["VendorDefinedDescriptorTitleString"] = records[i][
                    "VendorDefinedDescriptorTitleString"]
                desc_data = records[i]["VendorDefinedDescriptorData"]
                desc["VendorDefinedDescriptorData"] = '0x' + str(desc_data)
                if desc["VendorDefinedDescriptorTitleString"] == "APSKU":
                    # AP SKU on Retimer is just vendor id, not a real AP SKU ID. So skip
                    if "FWImage" in components[-1] and \
                        not "PCIeRetimer" in components[-1]["FWImage"]:
                        bin_ary = bytearray.fromhex(
                            desc_data[:-2])  # First byte is strap id
                        bin_ary.reverse()
                        ap_sku_id = ''.join(format(x, '02x') for x in bin_ary)
                        components[-1]["AP_SKU_ID"] = "0x" + ap_sku_id
                        desc["VendorDefinedDescriptorData"] = components[-1][
                            "AP_SKU_ID"]
            else:
                desc["AdditionalDescriptorData"] = self.decode_descriptor_data(
                    desc["AdditionalDescriptorType"],
                    records[i]["AdditionalDescriptorIdentifierData"])
            descriptors.append(desc)
        return descriptors

    def get_builder_json(self):
        """ 
        Get PLDM metadata in JSON format ingestible by the open src pkg builder tool
        OSS package builder script can be found here:
        https://github.com/openbmc/pldm/blob/master/tools/fw-update/pldm_fwup_pkg_creator.py
        """
        header_info = {
            "PackageHeaderIdentifier": self.header_map["PackageHeaderIdentifier"].replace('-', ''),
            "PackageHeaderFormatVersion": int(self.header_map["PackageHeaderFormatRevision"]),
            "PackageReleaseDateTime": Util.get_alt_time_format(
                self.header_map["PackageReleaseDateTime"]),
            "PackageVersionString": self.header_map["PackageVersionString"]}
        fw_id_area = []
        for device_records in self.full_header[
                'FirmwareDeviceIdentificationArea']['FirmwareDeviceIDRecords']:
            fw_id_rec = {
                "DeviceUpdateOptionFlags": Util.get_set_bit_indices(
                    device_records["DeviceUpdateOptionFlags"]),
                "ComponentImageSetVersionString": device_records["ComponentImageSetVersionString"],
                "ApplicableComponents": Util.get_set_bit_indices(
                    device_records["ApplicableComponents"]),
                "Descriptors": []
            }
            desc_list = []
            for descriptors in device_records["RecordDescriptors"]:
                if descriptors.get("InitialDescriptorType"):
                    data = descriptors.get("InitialDescriptorData")
                    data_len = len(data)
                    desc_data = {
                        "DescriptorType": descriptors.get("InitialDescriptorType"),
                        "DescriptorData": int.from_bytes(
                            data,
                            byteorder='big',
                            signed=False).to_bytes(data_len, 'big').hex()
                    }
                elif descriptors.get("AdditionalDescriptorType") == 65535:
                    desc_data = {
                        "DescriptorType": descriptors.get("AdditionalDescriptorType"),
                        "VendorDefinedDescriptorTitleString": descriptors.get(
                            "VendorDefinedDescriptorTitleString"),
                        "VendorDefinedDescriptorData": descriptors.get(
                            "VendorDefinedDescriptorData")
                    }
                else:
                    data = descriptors.get("AdditionalDescriptorIdentifierData")
                    data_len = len(data)
                    desc_data = {
                        "DescriptorType": descriptors.get("AdditionalDescriptorType"),
                        "DescriptorData": int.from_bytes(
                            data,
                            byteorder='big',
                            signed=False).to_bytes(data_len, 'big').hex()
                    }
                desc_list.append(desc_data)
            fw_id_rec["Descriptors"] = desc_list
            fw_id_area.append(fw_id_rec)
        comp_img_area = []
        for img_data in self.component_img_info_list:
            img_info = {
                "ComponentClassification": img_data["ComponentClassification"],
                "ComponentIdentifier": int(img_data["ComponentIdentifier"][2:], 16),
                "ComponentOptions": Util.get_set_bit_indices(img_data["ComponentOptions"]),
                "RequestedComponentActivationMethod": Util.get_set_bit_indices(
                    img_data['RequestedComponentActivationMethod']),
                "ComponentVersionString": img_data["ComponentVersionString"],
                "ComponentComparisonStamp": img_data["ComponentComparisonStamp"]
            }
            comp_img_area.append(img_info)
        self.pkg_builder_json = {
            "PackageHeaderInformation": header_info,
            "FirmwareDeviceIdentificationArea": fw_id_area,
            "ComponentImageInformationArea": comp_img_area
        }

    def get_full_metadata_json(self):
        """ Decode byte value descriptors for full package metadata command """
        for device_records in self.full_header[
                'FirmwareDeviceIdentificationArea']['FirmwareDeviceIDRecords']:
            device_records[
                'ApplicableComponents'] = self.get_applicable_component_index(
                    device_records['ApplicableComponents'])
            records = device_records["RecordDescriptors"]
            descriptors = []
            if len(records) == 0:
                continue
            desc = records[0]
            desc["InitialDescriptorType"] = Util.get_descriptor_type_name(
                records[0]["InitialDescriptorType"])
            desc["InitialDescriptorData"] = self.decode_descriptor_data(
                desc["InitialDescriptorType"], desc["InitialDescriptorData"])
            descriptors.append(desc)
            for i in range(1, len(records)):
                desc = records[i]
                desc[
                    "AdditionalDescriptorType"] = Util.get_descriptor_type_name(
                        records[i]["AdditionalDescriptorType"])
                if desc["AdditionalDescriptorType"] == 'Vendor Defined':
                    desc["VendorDefinedDescriptorTitleString"] = records[i][
                        "VendorDefinedDescriptorTitleString"]
                    desc_data = records[i]["VendorDefinedDescriptorData"]
                    desc["VendorDefinedDescriptorData"] = '0x' + str(desc_data)
                else:
                    desc[
                        "AdditionalDescriptorIdentifierData"] = self.decode_descriptor_data(
                            desc["AdditionalDescriptorType"],
                            desc["AdditionalDescriptorIdentifierData"])
                descriptors.append(desc)
            device_records["RecordDescriptors"] = descriptors

    def prepare_records_json(self):
        # pylint: disable=line-too-long
        """
        Prepares the JSON output for the tool.
        """
        package_json = {
            "PackageHeaderInformation": {},
            "FirmwareDeviceRecords": []
        }
        package_json["PackageHeaderInformation"]["PackageHeaderIdentifier"] = (
            self.header_map["PackageHeaderIdentifier"])
        package_json["PackageHeaderInformation"][
            "PackageHeaderFormatRevision"] = (
                self.header_map["PackageHeaderFormatRevision"])
        if package_json["PackageHeaderInformation"][
                "PackageHeaderFormatRevision"] != "1":
            return False, "The input firmware package version does not conform \
            to the format created by NVIDIA packaging tool."

        package_json["PackageHeaderInformation"]["PackageReleaseDateTime"] = (
            self.header_map["PackageReleaseDateTime"])
        package_json["PackageHeaderInformation"]["PackageVersionString"] = (
            self.header_map["PackageVersionString"])
        package_json['PackageHeaderInformation']["PackageSHA256"] = (
            Util.get_checksum_for_component_image(self.package))
        recordlist = []
        for record in self.fd_id_record_list:
            rec = {
                "ComponentImageSetVersionString": "",
                "DeviceDescriptors": [],
                "Components": []
            }
            components, name = self.get_applicable_components_names(record)
            if not components or not name:
                return False, "The input firmware package does not conform to \
                the format created by NVIDIA packaging tool."

            rec["DeviceDescriptors"] = self.get_formatted_descriptors(
                record, components)
            rec["Components"] = components
            rec["ComponentImageSetVersionString"] = name
            recordlist.append(rec)
        package_json["FirmwareDeviceRecords"] = recordlist
        json_string = json.dumps(package_json, indent=4)
        return True, json_string


def main():
    """
    Call upack parser and prepare output json
    """
    arg_parser = argparse.ArgumentParser(prog='fwpkg-unpack',
                                         description=\
    f"NVIDIA fwpkg-unpack v{UNPACK_TOOL_VERSION} The firmware package unpack tool performs\
    parsing of the firmware package and unpacking. The unpacker will extract all firmware\
    images from the package and create bin files for each.",
                                         allow_abbrev=False)
    arg_parser.add_argument(
        "file", help="Provide firmware package filename to unpack.", nargs='?')
    arg_group = arg_parser.add_mutually_exclusive_group(required=True)
    arg_group.add_argument(
        "--unpack",
        action='store_true',
        help="Unpack the firmware package and extract all component images.")
    arg_group.add_argument(
        "--show_pkg_content",
        action='store_true',
        help=
        "Provide package content description without extracting firmware images."
    )
    arg_group.add_argument(
        "--show_all_metadata",
        action='store_true',
        help=
        "Provide all PLDM metadata in package without extracting firmware images."
    )
    arg_group.add_argument(
        "--dump_builder_json",
        action='store_true',
        help=
        "Dump PLDM metadata to stdout in JSON format, " \
            "which shall be input to OSS PLDM package builder tool."
    )
    arg_parser.add_argument(
        "--outdir",
        help=
        "Provide path to the directory where unpacked FW files will be stored. \
    This option is used along with --unpack. \
    If this option not specified with --unpack, current directory is assumed as outdir. \
    Creates the directory at a given path if it does not exist.")
    arg_group.add_argument("--version",
                           action='store_true',
                           help="Show tool version.")
    arg_parser.add_argument(
        "--verbose",
        action='store_true',
        help=
        "Verbose Mode, This option is used along with --unpack or --show_pkg_content. \
        By using this command, debug prints from the code will be copied in a debug \
        logfile created in the same directory with name fwpkg_unpack_log.txt from\
        unpack tool.")
    tool_args = arg_parser.parse_args()

    pldm_parser = PLDMUnpack()
    pldm_parser.unpack = tool_args.unpack
    pldm_parser.verbose = tool_args.verbose

    if tool_args.show_pkg_content is True:
        pldm_parser.unpack = False

    if tool_args.version is True:
        print(f"NVIDIA fwpkg-unpack - version {UNPACK_TOOL_VERSION}")
        sys.exit(0)
    else:
        parser_status = pldm_parser.unpack_pldm_package(
            tool_args.file, tool_args.outdir)
        if parser_status is True:
            json_output = {}
            if tool_args.show_all_metadata is False:
                parser_status, json_output = pldm_parser.prepare_records_json()
                if not parser_status:
                    print("Status : Failed to prepare JSON records")
                    print("Path for LogFile ", Util.LOGFILE_PATH)
                    sys.exit(1)
                if tool_args.dump_builder_json:
                    pldm_parser.get_builder_json()
                    json_output = json.dumps(pldm_parser.pkg_builder_json,
                                            sort_keys=False,
                                            indent=4)
            else:
                pldm_parser.get_full_metadata_json()
                json_output = json.dumps(pldm_parser.full_header,
                                         sort_keys=False,
                                         indent=4)
            if tool_args.verbose is True:
                print(json_output)
            sys.exit(0)
        else:
            print("Status : Failed")
            print("Path for LogFile ", Util.LOGFILE_PATH)
            sys.exit(1)


if __name__ == "__main__":
    main()
