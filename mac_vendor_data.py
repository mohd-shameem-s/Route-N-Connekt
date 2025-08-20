# MAC Prefixes to Vendor Mapping
MAC_PREFIXES = {
    # Intel Corporation
    "C4:75:AB": "Intel Corporate",
    "F8:8F:CA": "Intel Corporate",
    "00:1B:21": "Intel Corporate",
    "c4:75:ab": "Intel Corporate",
    "98:bd:80": "Intel Corporate",
    "74:3A:F4": "Intel Corporate",
    
    # Xiaomi Communications
    "88:A3:03": "Xiaomi Communications Co Ltd",
    "40:4E:36": "Xiaomi Communications Co Ltd",
    "64:CC:22": "Xiaomi Communications Co Ltd",

    # D-Link International
    "34:60:F9": "D-Link International",
    "1C:AF:F7": "D-Link International",
    "C8:BE:19": "D-Link International",
    
    # TP-Link
    "9c:a2:f4": "TP-Link Corporation Limited",
    
    # Juniper
    "00:1B:21": "Juniper Networks",
    "60:c7:8d": "Juniper Networks",

    # Apple
    "A4:5E:60": "Apple, Inc.",
    "BC:92:6B": "Apple, Inc.",
    "8C:85:90": "Apple, Inc.",
    "8e:70:9e": "Apple, Inc.",

    # Samsung Electronics
    "AC:5F:3E": "Samsung Electronics Co.,Ltd",
    "78:25:AD": "Samsung Electronics Co.,Ltd",
    "38:83:45": "Samsung Electronics Co.,Ltd",

    # Cisco Systems
    "00:50:56": "Cisco Systems",
    "F4:8C:50": "Cisco Systems",
    "00:1A:6B": "Cisco Systems",

    # TP-Link
    "DC:4A:3E": "TP-Link Technologies",
    "AC:84:C6": "TP-Link Technologies",
    "28:EE:52": "TP-Link Technologies",

    # Hewlett Packard
    "B4:B5:2F": "Hewlett Packard",
    "D8:CF:9C": "Hewlett Packard",
    "C8:3D:97": "Hewlett Packard",

    # Dell
    "00:14:22": "Dell Inc.",
    "00:21:70": "Dell Inc.",
    "08:97:98": "Dell Inc.",

    # Huawei Technologies
    "60:A4:B7": "Huawei Technologies",
    "10:5F:49": "Huawei Technologies",
    "BC:1A:13": "Huawei Technologies",

    # Microsoft
    "E4:25:E7": "Microsoft",
    "D4:38:9C": "Microsoft",
    "F0:1D:BC": "Microsoft",
    
    # AzureWave
    "cc:47:40": "AzureWave Technology Inc.",
    "10:68:38": "AzureWave Technology Inc.",
    "00:1A:78": "AzureWave Technology Inc.",
    "00:e9:3a": "AzureWave Technology Inc.",
    "cc:47:40": "AzureWave Technology Inc.",
    "f8:54:f6": "AzureWave Technology Inc.",
    "10:68:38": "AzureWave Technology Inc.",
    "e8:fb:1c": "AzureWave Technology Inc.",
    "50:5a:65": "AzureWave Technology Inc.",
    "14:13:33": "AzureWave Technology Inc.",
    "f8:54:f6": "AzureWave Technology Inc.",
    "10:68:38": "AzureWave Technology Inc.",
    
    # Uniway Infocom
    "48:93:DC": "Uniway Infocom Pvt Ltd",
    
    # Motorola
    "c8:9f:0c": "Motorola Mobility LLC, a Lenovo Company",

    # Indra Heera Technology
    "F4:B6:C6": "Indra Heera Technology LLP",

    # Servercom India
    "A8:88:1F": "Servercom (India) Private Limited",

    # ZTE Corporation
    "50:0A:BC": "ZTE Corporation",
    "00:26:68": "ZTE Corporation",
    
    #NothingMobiles
    "2c:be:eb": "Nothing Technology Limited",
    
    # Huawai
    "00:1A:78": "HUAWEI TECHNOLOGIES CO .,LTD",
    "b0:08:75": "HUAWEI TECHNOLOGIES CO.,LTD",

    # Realme Mobile
    "A4:83:E7": "Realme Mobile",
    "B0:C5:59": "Realme Mobile",

    # OPPO Electronics
    "08:05:81": "OPPO Electronics",
    "5C:92:5E": "OPPO Electronics",
    "14:47:2D": "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD",

    # Vivo Mobile
    "54:78:1A": "vivo Mobile Communication Co., Ltd.",
    "94:53:30": "vivo Mobile Communication Co., Ltd.",
    "FC:1D:2A": "vivo Mobile Communication Co., Ltd.",
    
    # Cloud Networks
    "38:D5:7A": "CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.",
    "CC:5E:F8": "CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.",
    "F0:A6:54": "CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.",
    
    # Additional Vendors
    "30:65:EC": "Sony Corporation",  # Sony Devices
    "F0:B4:29": "Sony Corporation",  # Sony Devices
    "D4:3D:7E": "Acer Inc.",         # Acer Laptops/Desktops
    "60:36:DD": "Acer Inc.",         # Acer Laptops/Desktops
    "00:0C:42": "Nokia",            # Nokia Networks
    "00:1E:68": "Nokia",            # Nokia Networks

    # New Entries
    "00:1A:2B": "Lenovo",            # Lenovo Devices
    "D0:50:99": "ASUS",              # ASUS Devices
    "B8:27:EB": "Raspberry Pi Foundation",  # Raspberry Pi
    "A0:36:9F": "Amazon",            # Amazon Devices
    "C0:3F:D5": "Google",            # Google Devices
    "E4:5F:01": "Fitbit",            # Fitbit Devices
    "D4:3D:7E": "Acer",              # Acer Devices
    "A4:5E:60": "Apple",             # Apple Devices
}

# Vendor to Device Type Mapping
VENDOR_DEVICE_MAPPING = {
    # Routers
    "D-Link International": "Router",
    "TP-Link Technologies": "Router",
    "Cisco Systems": "Router",
    "Cisco Systems, Inc": "Router",
    "Huawei Technologies": "Router",
    "ZTE Corporation": "Router",
    "TP-Link Corporation Limited": "Router",

    # Laptops
    "Intel Corporate": "Laptop",
    "Dell Inc.": "Laptop",
    "Hewlett Packard": "Laptop",
    "Apple, Inc.": "Laptop",
    "Acer Inc.": "Laptop",  # Acer Laptops
    "Lenovo": "Laptop",      # Lenovo Laptops
    "ASUS": "Laptop",     # ASUS Laptops
    "AzureWave Technology Inc.": "Laptop",
        
    # Mobile Phones
    "Xiaomi Communications Co Ltd": "Mobile",
    "Samsung Electronics": "Mobile",
    "Apple": "Mobile",
    "HUAWEI TECHNOLOGIES CO.,LTD": "Mobile",
    "Realme Mobile": "Mobile",
    "OPPO Electronics": "Mobile",
    "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD": "Mobile",
    "vivo Mobile Communication Co., Ltd.": "Mobile",
    "CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.": "Mobile",
    "Motorola Mobility LLC, a Lenovo Company": "Mobile",
    "Google": "Mobile",       # Google Devices
    "Amazon": "Mobile",       # Amazon Devices
    "Fitbit": "Wearable", 
    "Nothing Technology Limited":"Mobile",
    "Liteon Technology Corporation": "Mobile",
    "CHONGQING FUGUI ELECTRONICS CO.,LTD.":"Mobile",
    "Chicony Electronics Co., Ltd.": "Mobile",
    "Hon Hai Precision Ind. Co.,Ltd.":"Mobile",

    # Desktop Computers
    "Microsoft": "Desktop",
    "Dell Inc.": "Desktop",
    "Hewlett Packard": "Desktop",

    # IoT Devices
    "Indra Heera Technology LLP": "IoT Device",
    "Uniway Infocom Pvt Ltd": "IoT Device",
    "Raspberry Pi Foundation": "IoT Device",  # Raspberry Pi

    # Servers
    "Cisco Systems": "Server",
    "Hewlett Packard": "Server",
    "Servercom (India) Private Limited": "Server",

    # Networking
    "Nokia": "Networking",
    "Sony Corporation": "Mobile",
}