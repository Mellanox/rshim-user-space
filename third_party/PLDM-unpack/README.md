# PLDM-unpack

> SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
>
> SPDX-License-Identifier: MIT

# Firmware Package Unpack Tool

The firmware unpack tool is a command line tool that parses and unpacks a firmware package built according to the PLDM firmware update specification v1.0.1.
The tool also shows metadata of the package, including device name, model, vendor, other uniquely identifying device descriptors, and version of the included firmware images. It provides the full path of each firmware image extracted from the package, and shows which image belongs to which component.

## Source Code

The source code is written in the file fwpkg-unpack.py which is a Python script. The tool requires Python 3.8

## Usage
<pre>
The tool supports the following options:
usage: python3 fwpkg_unpack.py --help
usage: fwpkg-unpack [-h] [--unpack] [--show_pkg_content] [--show_all_metadata] [--dump_builder_json] [--outdir OUTDIR] [--version] [--verbose] [file]

NVIDIA fwpkg-unpack v4.1.3 The firmware package unpack tool performs parsing of the firmware package and unpacking. The unpacker will extract all firmware images
from the package and create bin files for each.

positional arguments:
  file                 Provide firmware package filename to unpack.

optional arguments:
  -h, --help           show this help message and exit
  --unpack             Unpack the firmware package and extract all component images.
  --show_pkg_content   Provide package content description without extracting firmware images.
  --show_all_metadata  Provide all PLDM metadata in package without extracting firmware images.
  --dump_builder_json  Dump PLDM metadata to stdout in JSON format, which shall be input to OSS PLDM package builder tool.
  --outdir OUTDIR      Provide path to the directory where unpacked FW files will be stored. This option is used along with --unpack. If this option not
                       specified with --unpack, current directory is assumed as outdir. Creates the directory at a given path if it does not exist.
  --version            Show tool version.
  --verbose            Verbose Mode, This option is used along with --unpack or --show_pkg_content. By using this command, debug prints from the code will be
                       copied in a debug logfile created in the same directory with name fwpkg_unpack_log.txt from unpack tool.
</pre>

## Unpack Example
### --unpack command option
```
$ python3 fwpkg_unpack.py --unpack --outdir results/ nvfw_HGX-H100x8_0002_230517.3.0_prod-signed.fwpkg
```
```json
{
    "PackageHeaderInformation": {
        "PackageHeaderIdentifier": "f018878c-cb7d-4943-9800-a02f059aca02",
        "PackageHeaderFormatRevision": "1",
        "PackageReleaseDateTime": "2023-5-17 5:9:22:0 +0",
        "PackageVersionString": "HGX-H100x8_0002_230517.3.0",
        "PackageSHA256": "8a1fd39afea9d6c722ea311678f153d0808512c1f094a8f52c78fd35cc6872b6"
    },
    "FirmwareDeviceRecords": [
        {
            "ComponentImageSetVersionString": "ERoT,HMC::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x10"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x1a03"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x2600"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x0d2452"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "FWImage": "/home/results/ERoT_00.02.0134.0000_n00_image.bin",
                    "FWImageSHA256": "9eb61dadc27c859a9dd018d4044afc20dafbb17fdb17fb6fe216664a7feac329",
                    "SignatureType": "N/A",
                    "FWImageSize": 188928
                },
                {
                    "ComponentIdentifier": "0x10",
                    "ComponentVersionString": "HGX-22.10-1-rc36",
                    "FWImage": "/home/results/HMC_HGX-22.10-1-rc36_image.bin",
                    "FWImageSHA256": "e306a43ee097ed8f4ef302af8433fc96bad59b1e784c1a50625422dbc5bc2c3f",
                    "SignatureType": "N/A",
                    "FWImageSize": 67105792,
                    "AP_SKU_ID": "0x0d2452"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,FPGA::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x50"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x1172"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x0021"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x543210"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "FWImage": "/home/results/ERoT_00.02.0134.0000_n00_image.bin",
                    "FWImageSHA256": "9eb61dadc27c859a9dd018d4044afc20dafbb17fdb17fb6fe216664a7feac329",
                    "SignatureType": "N/A",
                    "FWImageSize": 188928
                },
                {
                    "ComponentIdentifier": "0x50",
                    "ComponentVersionString": "2.11",
                    "FWImage": "/home/results/FPGA_2.11_image.bin",
                    "FWImageSHA256": "f68274d43a656b357ccece8e9ab7d5878ee98a815ebab72fe0098ed47836b072",
                    "SignatureType": "N/A",
                    "FWImageSize": 32117760,
                    "AP_SKU_ID": "0x543210"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,GPU:GH100_HBM3-80GB-885_0200:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x20"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x2330"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x16c1"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x000437"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "FWImage": "/home/results/ERoT_00.02.0134.0000_n00_image.bin",
                    "FWImageSHA256": "9eb61dadc27c859a9dd018d4044afc20dafbb17fdb17fb6fe216664a7feac329",
                    "SignatureType": "N/A",
                    "FWImageSize": 188928
                },
                {
                    "ComponentIdentifier": "0x20",
                    "ComponentVersionString": "96.00.68.00.01",
                    "FWImage": "/home/results/GPU_GH100_HBM3-80GB-885_0200_96.00.68.00.01_image.bin",
                    "FWImageSHA256": "eef57ef849e0c46c4d196d106b109f7d9a8557ebfd49bd08277b9f5a7d546f6d",
                    "SignatureType": "N/A",
                    "FWImageSize": 975872,
                    "AP_SKU_ID": "0x000437"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,NVSwitch:LS10_0002_890_B00:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x70"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x22a3"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1796"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x0003b7"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "FWImage": "/home/results/ERoT_00.02.0134.0000_n00_image.bin",
                    "FWImageSHA256": "9eb61dadc27c859a9dd018d4044afc20dafbb17fdb17fb6fe216664a7feac329",
                    "SignatureType": "N/A",
                    "FWImageSize": 188928
                },
                {
                    "ComponentIdentifier": "0x70",
                    "ComponentVersionString": "96.10.38.00.01",
                    "FWImage": "/home/results/NVSwitch_LS10_0002_890_B00_96.10.38.00.01_image.bin",
                    "FWImageSHA256": "d854b8d89098ddc4943a551c31305f8b1d6b870ab4c71f6d83841c0df34cdb0c",
                    "SignatureType": "N/A",
                    "FWImageSize": 975872,
                    "AP_SKU_ID": "0x0003b7"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,PCIeSwitch::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x40"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x11f8"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x4028"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x000001"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "FWImage": "/home/results/ERoT_00.02.0134.0000_n00_image.bin",
                    "FWImageSHA256": "9eb61dadc27c859a9dd018d4044afc20dafbb17fdb17fb6fe216664a7feac329",
                    "SignatureType": "N/A",
                    "FWImageSize": 188928
                },
                {
                    "ComponentIdentifier": "0x40",
                    "ComponentVersionString": "1.7.5F",
                    "FWImage": "/home/results/PCIeSwitch_1.7.5F_image.bin",
                    "FWImageSHA256": "e8382a794afd0e84eb6146bfcb944aec5d50b35eae1aa4f176fab2a8d56330a5",
                    "SignatureType": "N/A",
                    "FWImageSize": 4461824,
                    "AP_SKU_ID": "0x000001"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "PCIeRetimer:P8:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "UUID",
                    "InitialDescriptorData": "0xef5eb98016d211ec8f40d45d64be4256"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x0001fa1d"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0x8000",
                    "ComponentVersionString": "1.31.8",
                    "FWImage": "/home/results/PCIeRetimer_P8_1.31.8_image.bin",
                    "FWImageSHA256": "13b214576fea1c1b9f02645bb949dca420a18cec904c39b48c27e43ccfd88a52",
                    "SignatureType": "N/A",
                    "FWImageSize": 262144
                }
            ]
        }
    ]
}
```
### --show_pkg_content command option
```
$ python3 fwpkg_unpack.py --show_pkg_content nvfw_HGX-H100x8_0002_230517.3.0_prod-signed.fwpkg
```
```json
{
    "PackageHeaderInformation": {
        "PackageHeaderIdentifier": "f018878c-cb7d-4943-9800-a02f059aca02",
        "PackageHeaderFormatRevision": "1",
        "PackageReleaseDateTime": "2023-5-17 5:9:22:0 +0",
        "PackageVersionString": "HGX-H100x8_0002_230517.3.0",
        "PackageSHA256": "8a1fd39afea9d6c722ea311678f153d0808512c1f094a8f52c78fd35cc6872b6"
    },
    "FirmwareDeviceRecords": [
        {
            "ComponentImageSetVersionString": "ERoT,HMC::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x10"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x1a03"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x2600"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x52240d10"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "ECSKUID": "0x49353681"
                },
                {
                    "ComponentIdentifier": "0x10",
                    "ComponentVersionString": "HGX-22.10-1-rc36",
                    "APSKUID": "0x52240d10"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,FPGA::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x50"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x1172"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x0021"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x10325450"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "ECSKUID": "0x49353681"
                },
                {
                    "ComponentIdentifier": "0x50",
                    "ComponentVersionString": "2.11",
                    "APSKUID": "0x10325450"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,GPU:GH100_HBM3-80GB-885_0200:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x20"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x2330"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x16c1"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x37040020"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "ECSKUID": "0x49353681"
                },
                {
                    "ComponentIdentifier": "0x20",
                    "ComponentVersionString": "96.00.68.00.01",
                    "APSKUID": "0x37040020"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,NVSwitch:LS10_0002_890_B00:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x70"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x22a3"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1796"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0xb7030070"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "ECSKUID": "0x49353681"
                },
                {
                    "ComponentIdentifier": "0x70",
                    "ComponentVersionString": "96.10.38.00.01",
                    "APSKUID": "0xb7030070"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "ERoT,PCIeSwitch::",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "IANA Enterprise ID",
                    "InitialDescriptorData": "0x00001647"
                },
                {
                    "AdditionalDescriptorType": "UUID",
                    "AdditionalDescriptorData": "0x162023c93ec5411595f448701d49d675"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "0x40"
                },
                {
                    "AdditionalDescriptorType": "PCI Vendor ID",
                    "AdditionalDescriptorData": "0x11f8"
                },
                {
                    "AdditionalDescriptorType": "PCI Device ID",
                    "AdditionalDescriptorData": "0x4028"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                    "AdditionalDescriptorData": "0x10de"
                },
                {
                    "AdditionalDescriptorType": "PCI Subsystem ID",
                    "AdditionalDescriptorData": "0x1643"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x01000040"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "0x49353681"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0xff00",
                    "ComponentVersionString": "00.02.0134.0000_n00",
                    "ECSKUID": "0x49353681"
                },
                {
                    "ComponentIdentifier": "0x40",
                    "ComponentVersionString": "1.7.5F",
                    "APSKUID": "0x01000040"
                }
            ]
        },
        {
            "ComponentImageSetVersionString": "PCIeRetimer:P8:",
            "DeviceDescriptors": [
                {
                    "InitialDescriptorType": "UUID",
                    "InitialDescriptorData": "0xef5eb98016d211ec8f40d45d64be4256"
                },
                {
                    "AdditionalDescriptorType": "Vendor Defined",
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "0x0001fa1d"
                }
            ],
            "Components": [
                {
                    "ComponentIdentifier": "0x8000",
                    "ComponentVersionString": "1.31.8",
                    "APSKUID": "0x0001fa1d"
                }
            ]
        }
    ]
}
```
### --show_all_metadata command option
```
$ python3 fwpkg_unpack.py --show_all_metadata nvfw_HGX-H100x8_0002_230517.3.0_prod-signed.fwpkg
```
```json
{
    "PackageHeaderInformation": {
        "PackageHeaderIdentifier": "f018878c-cb7d-4943-9800-a02f059aca02",
        "PackageHeaderFormatRevision": "1",
        "PackageHeaderSize": 1023,
        "PackageReleaseDateTime": "2023-5-17 5:9:22:0 +0",
        "ComponentBitmapBitLength": 8,
        "PackageVersionStringType": 1,
        "PackageVersionStringLength": 26,
        "PackageVersionString": "HGX-H100x8_0002_230517.3.0"
    },
    "FirmwareDeviceIdentificationArea": {
        "DeviceIDRecordCount": 6,
        "FirmwareDeviceIDRecords": [
            {
                "RecordLength": 121,
                "DescriptorCount": 9,
                "DeviceUpdateOptionFlags": 0,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 10,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    0,
                    1
                ],
                "ComponentImageSetVersionString": "ERoT,HMC::",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "IANA Enterprise ID",
                        "InitialDescriptorLength": 4,
                        "InitialDescriptorData": "0x00001647"
                    },
                    {
                        "AdditionalDescriptorType": "UUID",
                        "AdditionalDescriptorLength": 16,
                        "AdditionalDescriptorIdentifierData": "0x162023c93ec5411595f448701d49d675"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 13,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 10,
                        "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                        "VendorDefinedDescriptorData": "0x10"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1a03"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Device ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x2600"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1643"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0x52240d10"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "ECSKU",
                        "VendorDefinedDescriptorData": "0x49353681"
                    }
                ],
                "FirmwareDevicePackageData": ""
            },
            {
                "RecordLength": 122,
                "DescriptorCount": 9,
                "DeviceUpdateOptionFlags": 0,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 11,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    0,
                    2
                ],
                "ComponentImageSetVersionString": "ERoT,FPGA::",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "IANA Enterprise ID",
                        "InitialDescriptorLength": 4,
                        "InitialDescriptorData": "0x00001647"
                    },
                    {
                        "AdditionalDescriptorType": "UUID",
                        "AdditionalDescriptorLength": 16,
                        "AdditionalDescriptorIdentifierData": "0x162023c93ec5411595f448701d49d675"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 13,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 10,
                        "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                        "VendorDefinedDescriptorData": "0x50"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1172"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Device ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x0021"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1643"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0x10325450"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "ECSKU",
                        "VendorDefinedDescriptorData": "0x49353681"
                    }
                ],
                "FirmwareDevicePackageData": ""
            },
            {
                "RecordLength": 145,
                "DescriptorCount": 9,
                "DeviceUpdateOptionFlags": 0,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 34,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    0,
                    3
                ],
                "ComponentImageSetVersionString": "ERoT,GPU:GH100_HBM3-80GB-885_0200:",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "IANA Enterprise ID",
                        "InitialDescriptorLength": 4,
                        "InitialDescriptorData": "0x00001647"
                    },
                    {
                        "AdditionalDescriptorType": "UUID",
                        "AdditionalDescriptorLength": 16,
                        "AdditionalDescriptorIdentifierData": "0x162023c93ec5411595f448701d49d675"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 13,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 10,
                        "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                        "VendorDefinedDescriptorData": "0x20"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Device ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x2330"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x16c1"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0x37040020"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "ECSKU",
                        "VendorDefinedDescriptorData": "0x49353681"
                    }
                ],
                "FirmwareDevicePackageData": ""
            },
            {
                "RecordLength": 143,
                "DescriptorCount": 9,
                "DeviceUpdateOptionFlags": 0,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 32,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    0,
                    4
                ],
                "ComponentImageSetVersionString": "ERoT,NVSwitch:LS10_0002_890_B00:",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "IANA Enterprise ID",
                        "InitialDescriptorLength": 4,
                        "InitialDescriptorData": "0x00001647"
                    },
                    {
                        "AdditionalDescriptorType": "UUID",
                        "AdditionalDescriptorLength": 16,
                        "AdditionalDescriptorIdentifierData": "0x162023c93ec5411595f448701d49d675"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 13,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 10,
                        "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                        "VendorDefinedDescriptorData": "0x70"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Device ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x22a3"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1796"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0xb7030070"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "ECSKU",
                        "VendorDefinedDescriptorData": "0x49353681"
                    }
                ],
                "FirmwareDevicePackageData": ""
            },
            {
                "RecordLength": 128,
                "DescriptorCount": 9,
                "DeviceUpdateOptionFlags": 0,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 17,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    0,
                    5
                ],
                "ComponentImageSetVersionString": "ERoT,PCIeSwitch::",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "IANA Enterprise ID",
                        "InitialDescriptorLength": 4,
                        "InitialDescriptorData": "0x00001647"
                    },
                    {
                        "AdditionalDescriptorType": "UUID",
                        "AdditionalDescriptorLength": 16,
                        "AdditionalDescriptorIdentifierData": "0x162023c93ec5411595f448701d49d675"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 13,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 10,
                        "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                        "VendorDefinedDescriptorData": "0x40"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x11f8"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Device ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x4028"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem Vendor ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x10de"
                    },
                    {
                        "AdditionalDescriptorType": "PCI Subsystem ID",
                        "AdditionalDescriptorLength": 2,
                        "AdditionalDescriptorIdentifierData": "0x1643"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0x01000040"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "ECSKU",
                        "VendorDefinedDescriptorData": "0x49353681"
                    }
                ],
                "FirmwareDevicePackageData": ""
            },
            {
                "RecordLength": 62,
                "DescriptorCount": 2,
                "DeviceUpdateOptionFlags": 1,
                "ComponentImageSetVersionStringType": 1,
                "ComponentImageSetVersionStringLength": 15,
                "FirmwareDevicePackageDataLength": 0,
                "ApplicableComponents": [
                    6
                ],
                "ComponentImageSetVersionString": "PCIeRetimer:P8:",
                "RecordDescriptors": [
                    {
                        "InitialDescriptorType": "UUID",
                        "InitialDescriptorLength": 16,
                        "InitialDescriptorData": "0xef5eb98016d211ec8f40d45d64be4256"
                    },
                    {
                        "AdditionalDescriptorType": "Vendor Defined",
                        "AdditionalDescriptorLength": 11,
                        "VendorDefinedDescriptorTitleStringType": 1,
                        "VendorDefinedDescriptorTitleStringLength": 5,
                        "VendorDefinedDescriptorTitleString": "APSKU",
                        "VendorDefinedDescriptorData": "0x0001fa1d"
                    }
                ],
                "FirmwareDevicePackageData": ""
            }
        ]
    },
    "ComponentImageInformationArea": {
        "ComponentImageCount": 7,
        "ComponentImageInformation": [
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0xff00",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 1023,
                "ComponentSize": 188928,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 19,
                "ComponentVersionString": "00.02.0134.0000_n00"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x10",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 189951,
                "ComponentSize": 67105792,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 16,
                "ComponentVersionString": "HGX-22.10-1-rc36"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x50",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 67295743,
                "ComponentSize": 32117760,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 4,
                "ComponentVersionString": "2.11"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x20",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 99413503,
                "ComponentSize": 975872,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 14,
                "ComponentVersionString": "96.00.68.00.01"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x70",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 100389375,
                "ComponentSize": 975872,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 14,
                "ComponentVersionString": "96.10.38.00.01"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x40",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 101365247,
                "ComponentSize": 4461824,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 6,
                "ComponentVersionString": "1.7.5F"
            },
            {
                "ComponentClassification": 10,
                "ComponentIdentifier": "0x8000",
                "ComponentComparisonStamp": 4294967295,
                "ComponentOptions": 1,
                "RequestedComponentActivationMethod": 0,
                "ComponentLocationOffset": 105827071,
                "ComponentSize": 262144,
                "ComponentVersionStringType": 1,
                "ComponentVersionStringLength": 6,
                "ComponentVersionString": "1.31.8"
            }
        ]
    },
    "Package Header Checksum": 3701773251
}
```
### --dump_builder_json command option
#### This output can be used as metadata JSON input for the OSS PLDM package creator tool available here 
https://github.com/openbmc/pldm/blob/master/tools/fw-update/pldm_fwup_pkg_creator.py
```
$ python3 fwpkg_unpack.py --dump_builder_json nvfw_GB200-P4975_0004_240819.1.0_custom_prod-signed.fwpkg
```
```json
{
    "PackageHeaderInformation": {
        "PackageHeaderIdentifier": "f018878ccb7d49439800a02f059aca02",
        "PackageHeaderFormatVersion": 1,
        "PackageReleaseDateTime": "19/08/2024 07:00:30",
        "PackageVersionString": "GB200-P4975_0004_240819.1.0_custom"
    },
    "FirmwareDeviceIdentificationArea": [
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "ERoT,HMC:SKU_179:",
            "ApplicableComponents": [
                0,
                1
            ],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "47160000"
                },
                {
                    "DescriptorType": 2,
                    "DescriptorData": "162023c93ec5411595f448701d49d675"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "10"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "b3000010"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "4d35368b"
                }
            ]
        },
        {
            "DeviceUpdateOptionFlags": [
                0
            ],
            "ComponentImageSetVersionString": "CPLD:MAX10:",
            "ApplicableComponents": [
                2
            ],
            "Descriptors": [
                {
                    "DescriptorType": 2,
                    "DescriptorData": "f65ec98a70e84e3da6c18d9f2b51d3e0"
                }
            ]
        },
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "ERoT,SBIOS:C01_2P_894:",
            "ApplicableComponents": [
                0,
                3
            ],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "47160000"
                },
                {
                    "DescriptorType": 2,
                    "DescriptorData": "162023c93ec5411595f448701d49d675"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "38"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "23000038"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "4d35368b"
                }
            ]
        },
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "ERoT,SMR::",
            "ApplicableComponents": [
                0,
                4
            ],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "47160000"
                },
                {
                    "DescriptorType": 2,
                    "DescriptorData": "162023c93ec5411595f448701d49d675"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "GLACIERDSD",
                    "VendorDefinedDescriptorData": "50"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "03040250"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "ECSKU",
                    "VendorDefinedDescriptorData": "4d35368b"
                }
            ]
        },
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "GPU:GB100_SKU201_ES2:",
            "ApplicableComponents": [
                5
            ],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "47160000"
                },
                {
                    "DescriptorType": 2,
                    "DescriptorData": "7865bed953204b6ab94d8fa70b6283d6"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "f6050000"
                }
            ]
        },
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "GPU:GB100_SKU201_ES2:",
            "ApplicableComponents": [
                6
            ],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "47160000"
                },
                {
                    "DescriptorType": 2,
                    "DescriptorData": "7865bed953204b6ab94d8fa70b6283d6"
                },
                {
                    "DescriptorType": 65535,
                    "VendorDefinedDescriptorTitleString": "APSKU",
                    "VendorDefinedDescriptorData": "f7050000"
                }
            ]
        }
    ],
    "ComponentImageInformationArea": [
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 65280,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "01.03.0183.0000_n04",
            "ComponentComparisonStamp": "0x0103b700"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 16,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "GB200Nvl-24.08-6",
            "ComponentComparisonStamp": "0x00240806"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 0,
            "ComponentOptions": [
                0
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "0.1C",
            "ComponentComparisonStamp": "0xffffffff"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 56,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "02.02.03",
            "ComponentComparisonStamp": "0x24080822"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 80,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "1.0A",
            "ComponentComparisonStamp": "0x312e3041"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 49152,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "97.00.13.00.00",
            "ComponentComparisonStamp": "0x01300000"
        },
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 49152,
            "ComponentOptions": [
                1
            ],
            "RequestedComponentActivationMethod": [],
            "ComponentVersionString": "97.00.13.00.00",
            "ComponentComparisonStamp": "0x01300000"
        }
    ]
}
```