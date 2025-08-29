# FastBook Unpacker

Using this script, you can unpack `radio-*.img` files from Google Pixel factory images and OTA updates. To extract the `modem.bin`, you have to first unpack the FastBook packed file (with magic `FBPK`) and then, mount the extracted image into a directory. For example:

```bash
./fbpacktool.py unpack radio-oriole-g5123b-145971-250328-b-13284995.img  # creates modem.img
mkdir modem.dir
sudo mount -v -o loop modem.img modem.dir
# You can find modem.bin under modem.dir/images/g5123b-145971-250328-B-13284995/
sudo umount modem.dir  # when you're done
```