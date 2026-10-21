# SBT-DF204 Case Study 3: Investigating Memory Evidence

Individual memory forensics investigation of a Windows 7 memory image, completed for the **SBT-DF204 Computer Forensics Case Studies** course at the International Cybersecurity and Digital Forensics Academy.

**Case title:** Investigating Suspected Illegal File Transfer From Memory Evidence
**Author:** Nebeuwa Ifeanyichukwu Raphael (Reg. No. 202520850LE)
**Submission date:** 19/10/2026

> This is academic coursework on a supplied lab image. No live system or real person was investigated, and no endpoint was contacted during the examination.

---

## Objective

Examine `memdumpWin7.mem` offline and answer three questions separately:

1. Is there evidence of an **attempted** file transfer?
2. Is there evidence of a **completed** transfer?
3. Can the activity be **attributed** to a specific person?

## Summary of findings

| Question | Confidence | Basis |
|---|---|---|
| Attempted transfer sequence | **Moderate** | Chrome (PID 2388) memory references `http://192.168.56.5/secret_file.docx`. `cmd.exe` (PID 3996) ran `cd Downloads` then `copy secret_file.docx F:`. Drive F: maps to a USB mass-storage device. |
| Completed transfer | **Low** | The console printed "1 file(s) copied", but `filescan` found no file object and ShellBags contain no F:\ entry. |
| Actor attribution | **Low** | Evidence links the commands to the `IEUser` account only. It does not identify the person at the keyboard, and the `sshd` service and `sshd_server` profile are an alternative explanation that is not ruled out. |

Full detail, the UTC timeline and the limitations are in the report.

## Evidence and integrity

| Item | Value |
|---|---|
| Evidence file | `memdumpWin7.mem` (Windows 7 memory image) |
| Size | 1,073,676,288 bytes |
| SHA-256 (original) | `500bc1ba8b5ffa8053b6213d7e7aae0c84c18cce541dc53a55887e6e5099495e` |
| SHA-256 (working copy) | `500bc1ba8b5ffa8053b6213d7e7aae0c84c18cce541dc53a55887e6e5099495e` (identical) |
| Image time | 2019-01-06 15:09:06 UTC (07:09:06 -0800 local) |
| Time zone | Pacific Standard Time (Bias 480 = UTC-8) |

Precautions taken: hashed the original before analysis, set it read-only (`chmod 444`), worked only on a copy, re-hashed the copy, saved every output with `tee`, and never contacted `192.168.56.5`.

## Environment

- Kali Linux
- Volatility Foundation Volatility Framework **2.6.1**, run as `python2 vol.py`
- Profile: `Win7SP1x86_23418`
- `pycryptodome` installed so registry plugins load
- `distorm3` and `yara` not installed, so `apihooks`, `threads`, `ssdt` and `yarascan` were unavailable and not used
- GNU `strings`, `grep`, `sha256sum`, `cp`, `chmod`

## Repository structure

```
SBT_DF204_Case_Study_3_Investigating_Memory_Evidence/
├── README.md
├── .gitignore
├── SBTDF204_CaseStudy3_202520850LE.docx.pdf       # final report (includes screenshots, Appendix A)
├── integrity/
│   ├── original_sha256.txt
│   └── working_sha256.txt
└── volatility-output/
    ├── out_imageinfo.txt                          # E02
    ├── out_pslist.txt                             # E03
    ├── out_netscan.txt                            # E04
    ├── out_timezone.txt                           # E05
    ├── out_cmdscan.txt                            # E06
    ├── out_consoles.txt                           # E07
    ├── out_hivelist.txt                           # E08
    ├── out_getsids_cmd.txt                        # E09
    ├── out_usbstor.txt                            # E10
    ├── out_mounteddevices.txt                     # E11
    ├── out_mountpoints2.txt                       # E12
    ├── out_strings_ip.txt, ip_strings.txt         # E13
    ├── out_profilelist.txt                        # E14
    ├── out_sam_names.txt                          # E15
    ├── out_strings_pid.txt                        # E16
    ├── out_profile_1000.txt, out_profile_1002.txt # E17
    ├── out_deviceclasses.txt                      # E18
    ├── out_mp2_F.txt, out_mp2_guid.txt            # E19
    ├── out_usbstor_instance.txt                   # E20
    ├── out_dc_usb_link.txt                        # E21
    ├── out_filescan_secret.txt, out_filescan_wide.txt  # E22
    ├── shellbags.html, shellbags_text.txt         # E23
    └── out_yara_ip.txt                            # limitation: Yara not installed
```

## Methodology

In the commands below, `V` stands for:

```bash
python2 vol.py -f ../memdump_working.mem --profile=Win7SP1x86_23418
```

**1. Preserve the evidence**

```bash
sha256sum memdumpWin7.mem | tee original_sha256.txt
chmod 444 memdumpWin7.mem
cp memdumpWin7.mem memdump_working.mem
sha256sum memdump_working.mem | tee working_sha256.txt
```

**2. Identify the profile and image time**

```bash
python2 vol.py -f ../memdump_working.mem imageinfo | tee ../out_imageinfo.txt
```

**3. Processes and network**

```bash
V pslist  | tee ../out_pslist.txt
V netscan | tee ../out_netscan.txt
```

**4. Accounts**

```bash
V hivelist | tee ../out_hivelist.txt
V getsids -p 3996 | tee ../out_getsids_cmd.txt
V printkey -K "SAM\Domains\Account\Users\Names"
V printkey -K "Microsoft\Windows NT\CurrentVersion\ProfileList"
```

**5. Command history**

```bash
V cmdscan  | tee ../out_cmdscan.txt
V consoles | tee ../out_consoles.txt
```

**6. Removable media**

```bash
V printkey -K "ControlSet001\Enum\USBSTOR"
V printkey -K "MountedDevices"
V printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
```

**7. Memory strings for the server address**

```bash
strings -a -t d ../memdump_working.mem | grep -F "192.168.56.5" > ../ip_strings.txt
V strings -s ../ip_strings.txt | tee ../out_strings_pid.txt
```

**8. File and folder evidence**

```bash
V filescan | grep -i "secret_file"
V shellbags --output=html --output-file=../shellbags.html
```

## Evidence ID index

Each finding in the report cites an evidence ID (E01 to E23). The IDs match the output files in `volatility-output/` and the figures in `screenshots/`. Appendix B of the report holds the full evidence log, and Appendix C holds selected output excerpts.

## Limitations

- Single memory snapshot at 15:09:06 UTC, with no per-command timestamps.
- The two TCP connections to `192.168.56.5:80` are CLOSED with no owning process, and many string hits sit in free memory.
- No independent confirmation that the copy to F: succeeded.
- The USB instance ID has no serial number, so the device cannot be uniquely identified.
- `FTK Imager.exe` was running before capture (15:07:15).
- Some timestamps do not fit the image time (for example 18:02:44-45, 15:09:07 and 16:31:39). They were treated as unreliable and kept out of the timeline.

## How to reproduce

1. Obtain `memdumpWin7.mem` from the course materials (it is **not** included in this repo).
2. Hash it and confirm the SHA-256 above.
3. Install Volatility 2.6.1 on Kali with `pycryptodome`.
4. Run the commands in the Methodology section against a working copy.
5. Compare your output with the files in `volatility-output/`.

## `.gitignore`

```
memdumpWin7.mem
memdump_working.mem
*.mem
```
