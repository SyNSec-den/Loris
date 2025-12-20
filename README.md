# Loris
Loris is a stateful fuzz testing framework designed to explore and analyze baseband firmware.
For details, please check out our paper, "Stateful Analysis and Fuzzing of Commercial Baseband Firmware" (IEEE S&P 2025).

## Emulator
To emulate 5G basebands, run `just emulate` to build the Docker container. A small set of tested modem binaries is available under `/binaries`. For example, to emulate the Pixel 6 modem, run:
```bash
./firmwire.py /binaries/oriole-bp3a.250905.014/modem.bin
```

## BibTex
<a href="https://syed-rafiul-hussain.github.io/wp-content/uploads/2025/05/Loris_baseband_fuzzing_sp25.pdf"> <img title="" src="https://github.com/user-attachments/assets/28481502-f3d8-4eba-9f40-98f290b4e08f" alt="Loris thumbnail" align="right" width="200"></a>
If you are using Loris in an academic paper please use this to cite it:
```
@INPROCEEDINGS{ranjbar_loris_2025,
  author = { Ranjbar, Ali and Yang, Tianchang and Tu, Kai and Khalilollahi, Saaman and Hussain, Syed Rafiul },
  booktitle = { 2025 IEEE Symposium on Security and Privacy (SP) },
  title = {{ Stateful Analysis and Fuzzing of Commercial Baseband Firmware }},
  year = {2025},
  ISSN = {2375-1207},
  pages = {1120-1139},
  doi = {10.1109/SP61157.2025.00143},
  url = {https://doi.ieeecomputersociety.org/10.1109/SP61157.2025.00143},
  publisher = {IEEE Computer Society},
  address = {Los Alamitos, CA, USA},
  month = May
}
```
