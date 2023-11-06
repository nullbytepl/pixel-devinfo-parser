# Google Pixel devinfo parser
This is a very simple tool to parse the `devinfo` partition that's present on many Google Pixel devices.
The partition contains various factory-provisioned information, such as:
* The board ID and revision
* The device color
* The device SKU
* The Bluetooth and WiFi MAC
* The S/N
* More

**NOTE: I STRONGLY RECOMMEND AGAINST MODIFYING DEVINFO, AS IT MIGHT LEAD TO MAJOR ISSUES. DO IT AT YOUR OWN RISK. I PROVIDE NO TOOLS TO DO THIS.**

### Compatible devices
Tested devices:
* Pixel 8 Pro (HW MP, v3.8)
* Pixel 7 Pro (HW MP, v3.8)
* Pixel 6a (HW MP, v3.5)
* Pixel 6 Pro (HW MP, v3.5)

The tool should work fine on any Tensor-based Pixel.

### Usage
`python ./di.py /path/to/devinfo.img`