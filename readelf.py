#/usr/bin/env python
#Check offsets

import sys
import binascii

def change_endianess(hexstr):
	tmp = []
	for i in range(0,len(hexstr),2):
		tmp.insert(0,hexstr[i:i+2])
	return ''.join(tmp)

def print_ELF_Header(hexFile):
#must check arrays boundaries
	
	eident = hexFile[0:32]
	eiClass = eident[8:10]
	eiData = eident[10:12]
	eiVersion = eident[12:14]
	eiPad = eident[14:]
	
	print "ELF Header:"
	print "\tMagic:\t\t"+eident
	
	tmpClass = {}
	tmpClass['00'] = "ELF_CLASS_NONE\t(00)"
	tmpClass['01'] = "ELF_CLASS_32\t(01)"
	tmpClass['02'] = "ELF_CLASS_64\t(02)"
	
	print "\tClass:\t\t"+tmpClass[eiClass]
	
	tmpData = {}
	tmpData['00'] = "ELF_DATA_NONE"
	tmpData['01'] = "ELF_DATA_2_LSB\t(2's complement - little-endian)"
	tmpData['02'] = "ELF_DATA_2_MSB\t(2's complements - big-endian)"
	
	print "\tData:\t\t"+tmpData[eiData]
	
	tmpVersion = {}
	tmpVersion['01'] = "Current\t\t(01)"
	tmpVersion['00'] = "Invalid\t\t(00)"
	
	print "\tVersion:\t"+tmpVersion[eiVersion] 
	
	if eiPad != '000000000000000000':
		print "Find hidden data in e_ident[EI_PAD] in the elf header: "+eipad
		
	etype = hexFile[32:36]
	emachine = hexFile[36:40]
	eversion = hexFile[40:48]
	
	if eiClass == '01':
		n = 8
	else:
		n = 16

	eentry = hexFile[48:48+n]
	ephoff = hexFile[48+n:48+2*n]
	eshoff = hexFile[48+2*n:48+3*n]
	offset = 48+3*n
	eflags = hexFile[offset:offset+8]
        ehsize = hexFile[offset+8:offset+12]
       	ephentsize = hexFile[offset+12:offset+16]
        ephnum = hexFile[offset+16:offset+20]
       	eshentsize = hexFile[offset+20:offset+24]
        eshnum = hexFile[offset+24:offset+28]
       	eshstrndx = hexFile[offset+28:offset+32]

	tmpType = {}
	tmpType['0000'] = 'ET_NONE\t\t(No file type)'
	tmpType['0100'] = 'ET_REL\t\t(Relocatable file)'
	tmpType['0200'] = 'ET_EXEC\t\t(Executable file)'
	tmpType['0300'] = 'ET_DYN\t\t(Shared object file)'
	tmpType['0400'] = 'ET_CORE\t\t(Core file)'
	tmpType['ff00'] = 'ET_LOPROC\t\t(Processor-specific)'
	tmpType['ffff'] = 'ET_HIPROC\t\t(Processor-specific)'
	
	print "\tType:\t\t" +tmpType[etype]

	tmpMachine = {}
	tmpMachine['0000'] = 'EM_NONE (No machine)'
	tmpMachine['0100'] = 'EM_M32 (AT&T WE 32100)'
	tmpMachine['0200'] = 'EM_SPARC (SPARC)'
	tmpMachine['0300'] = 'EM_386 (Intel 386)'
	tmpMachine['0400'] = 'EM_68k (Motorola 68000)'
        tmpMachine['0500'] = 'EM_88k (Motorola 88000)'
        tmpMachine['0600'] = 'EM_IAMCU (Intel MCU)'
	tmpMachine['0700'] = 'EM_860 (Intel 80860)'
        tmpMachine['0800'] = 'EM_MIPS (MIPS R3000)'
        tmpMachine['0900'] = 'EM_S370 (IBM System/370)'
        tmpMachine['0a00'] = 'EM_MIPS_RS3_LE (MIPS RS3000 Little-endian)'
	tmpMachine['0f00'] = 'EM_PARISC (Hewlett-Packard PA-RISC)'
	tmpMachine['1100'] = 'EM_SPARC32PLUS (Enhanced instruction set SPARC)'
	tmpMachine['1200'] = 'EM_960 (Intel 80960)'
	tmpMachine['1300'] = 'EM_PPC (PowerPC)'
	tmpMachine['1400'] = 'EM_PPC64 (PowerPC64)'
	tmpMachine['1500'] = 'EM_S390 (IBM System/390)'
	tmpMachine['1600'] = 'EM_SPU (IBM SPU/SPC)'
	tmpMachine['2400'] = 'EM_V800 (NEC V800)'
	tmpMachine['2500'] = 'EM_FR20 (Fujitsu FR20)'
	tmpMachine['2600'] = 'EM_RH32 (TRW RH-32)'
	tmpMachine['2700'] = 'EM_RCE (Motorola RCE)'
	tmpMachine['2800'] = 'EM_ARM (ARM)'
	tmpMachine['2900'] = 'EM_ALPHA (DEC Alpha)'
	tmpMachine['2a00'] = 'EM_SH (Hitachi SH)'
        tmpMachine['2b00'] = 'EM_SPARCV9 (SPARC V9)'
	tmpMachine['2c00'] = 'EM_TRICORE (Siemens TriCore)'
        tmpMachine['2d00'] = 'EM_ARC (Argonaut RISC Core)'
	tmpMachine['2e00'] = 'EM_H8_300 (Hitachi H8/300)'
        tmpMachine['2f00'] = 'EM_H8_300H (Hitachi H8/300H)'
	tmpMachine['3000'] = 'EM_H8S (Hitachi H8S)'
        tmpMachine['3100'] = 'EM_H8_500 (Hitachi H8/500)'
	tmpMachine['3200'] = 'EM_IA_64 (Intel IA-64 processor architecture)'
        tmpMachine['3300'] = 'EM_MIPS_X (Stanford MIPS-X)'
	tmpMachine['3400'] = 'EM_COLDFIRE (Motorola ColdFire)'
        tmpMachine['3500'] = 'EM_68HC12 (Motorola M68HC12)'
	tmpMachine['3600'] = 'EM_MMA (Fujitsu MMA Multimedia Accelerator)'
        tmpMachine['3700'] = 'EM_PCP (Siemens PCP)'
	tmpMachine['3800'] = 'EM_NCPU (Sony nCPU embedded RISC processor)'
        tmpMachine['3900'] = 'EM_NDR1 (Denso NDR1 microprocessor)'
	tmpMachine['3a00'] = 'EM_STARCORE (Motorola Star*Core processor)'
        tmpMachine['3b00'] = 'EM_ME16 (Toyota ME16 processor)'
        tmpMachine['3c00'] = 'EM_ST100 (STMicroelectronics ST100 processor)'
        tmpMachine['3d00'] = 'EM_TINYJ (Advanced Logic Corp. TinyJ embedded processor family)'
        tmpMachine['3e00'] = 'EM_X86_64 (AMD x86-64 architecture)'
        tmpMachine['3f00'] = 'EM_PDSP (Sony DSP Processor)'
        tmpMachine['4000'] = 'EM_PDP10 (Digital Equipment Corp. PDP-10)'
        tmpMachine['4100'] = 'EM_PDP11 (Digital Equipment Corp. PDP-11)'
        tmpMachine['4200'] = 'EM_FX66 (Siemens FX66 microcontroller)'
        tmpMachine['4300'] = 'EM_ST9PLUS (STMicroelectronics ST9+ 8/16 bit microcontroller)'
        tmpMachine['4400'] = 'EM_ST7 (STMicroelectronics ST7 8-bit microcontroller)'
        tmpMachine['4500'] = 'EM_68HC16 (Motorola MC68HC16 Microcontroller)'
        tmpMachine['4600'] = 'EM_68HC11 (Motorola MC68HC11 Microcontroller)'
        tmpMachine['4700'] = 'EM_68HC08 (Motorola MC68HC08 Microcontroller)'
        tmpMachine['4800'] = 'EM_68HC05 (Motorola MC68HC05 Microcontroller)'
        tmpMachine['4900'] = 'EM_SVX (Silicon Graphics SVx)'
        tmpMachine['4a00'] = 'EM_ST19 (STMicroelectronics ST19 8-bit microcontroller)'
        tmpMachine['4b00'] = 'EM_VAX (Digital VAX)'
        tmpMachine['4c00'] = 'EM_CRIS (Axis Communications 32-bit embedded processor)'
        tmpMachine['4d00'] = 'EM_JAVELIN (Infineon Technologies 32-bit embedded processor)'
        tmpMachine['4e00'] = 'EM_FIREPATH (Element 14 64-bit DSP Processor)'
        tmpMachine['4f00'] = 'EM_ZSP (LSI Logic 16-bit DSP Processor)'
        tmpMachine['5000'] = 'EM_MMIX (Donald Knuth\'s educational 64-bit processor)'
        tmpMachine['5100'] = 'EM_HUANY (Harvard University machine-independent object files)'
        tmpMachine['5200'] = 'EM_PRISM (SiTera Prism)'
        tmpMachine['5300'] = 'EM_AVR (Atmel AVR 8-bit microcontroller)'
        tmpMachine['5400'] = 'EM_FR30 (Fujitsu FR30)'
        tmpMachine['5500'] = 'EM_D10V (Mitsubishi D10V)'
        tmpMachine['5600'] = 'EM_D30V (Mitsubishi D30V)'
        tmpMachine['5700'] = 'EM_V850 (NEC v850)'
        tmpMachine['5800'] = 'EM_M32R (Mitsubishi M32R)'
        tmpMachine['5900'] = 'EM_MN10300 (Matsushita MN10300)'
        tmpMachine['5a00'] = 'EM_MN10200 (Matsushita MN10200)'
        tmpMachine['5b00'] = 'EM_PJ (picoJava)'
        tmpMachine['5c00'] = 'EM_OPENRISC (OpenRISC 32-bit embedded processor)'
        tmpMachine['5d00'] = 'EM_ARC_COMPACT (ARC International ARCompact processor)' 
        tmpMachine['5e00'] = 'EM_XTENSA (Tensilica Xtensa Architecture)'
        tmpMachine['5f00'] = 'EM_VIDEOCORE (Alphamosaic VideoCore processor)'
        tmpMachine['6000'] = 'EM_TMM_GPP (Thompson Multimedia General Purpose Processor)'
        tmpMachine['6100'] = 'EM_NS32K (National Semiconductor 32000 series)'
        tmpMachine['6200'] = 'EM_TPC (Tenor Network TPC processor)'
        tmpMachine['6300'] = 'EM_SNP1K (Trebia SNP 1000 processor)'
        tmpMachine['6400'] = 'EM_ST200 (STMicroelectronics)'
        tmpMachine['6500'] = 'EM_IP2K (Ubicom IP2xxx microcontroller family)'
        tmpMachine['6600'] = 'EM_MAX (MAX Processor)'
        tmpMachine['6700'] = 'EM_CR (National Semiconductor CompactRISC microprocessor)'
        tmpMachine['6800'] = 'EM_F2MC16 (Fujitsu F2MC16)'
        tmpMachine['6900'] = 'EM_MSP430 (Texas Instruments embedded microcontroller msp430)'
        tmpMachine['6a00'] = 'EM_BLACKFIN (Analog Devices Blackfin (DSP) processor)'
        tmpMachine['6b00'] = 'EM_SE_C33 (S1C33 Family of Seiko Epson processors)'
        tmpMachine['6c00'] = 'EM_SEP (Sharp embedded microprocessor)'
        tmpMachine['6d00'] = 'EM_ARCA (Arca RISC Microprocessor)'
        tmpMachine['6e00'] = 'EM_UNICORE (Microprocessor series from PKU-Unity Ltd. and MPRC)'
        tmpMachine['6f00'] = 'EM_EXCESS (eXcess: 16/32/64-bit configurable embedded CPU)'
        tmpMachine['7000'] = 'EM_DXP (Icera Semiconductor Inc. Deep Execution Processor)'
        tmpMachine['7100'] = 'EM_ALTERA_NIOS2 (Altera Nios II soft-core processor)'
        tmpMachine['7200'] = 'EM_CRX (National Semiconductor CompactRISC CRX)'
        tmpMachine['7400'] = 'EM_C166 (Infineon C16x/XC16x processor)'
        tmpMachine['7500'] = 'EM_M16C (Renesas M16C series microprocessors)'
        tmpMachine['7600'] = 'EM_DSPIC30F (Microchip Technology dsPIC30F Digital Signal Controller)'
        tmpMachine['7700'] = 'EM_CE (Freescale Communication Engine RISC core)'
        tmpMachine['8300'] = 'EM_M32C (Renesas M32C series microprocessors)'
        tmpMachine['8400'] = 'EM_TSK3000 (Altium TSK3000 core)'
        tmpMachine['8500'] = 'EM_RS08 (Freescale RS08 embedded processor)'
        tmpMachine['8600'] = 'EM_SHARC (Analog Devices SHARC family of 32-bit DSP)'
        tmpMachine['8700'] = 'EM_ECOG2 (Cyan Technology eCOG2 microprocessor)'
	tmpMachine['8800'] = 'EM_SCORE7 (Sunplus S+core7 RISC processor)'
        tmpMachine['8900'] = 'EM_DSP24 (New Japan Radio (NJR) 24-bit DSP Processor)'
        tmpMachine['8a00'] = 'EM_VIDEOCORE3 (Broadcom VideoCore III processor)'
        tmpMachine['8b00'] = 'EM_LATTICEMICO32 (RISC processor for Lattice FPGA architecture)'
        tmpMachine['8c00'] = 'EM_SE_C17 (Seiko Epson C17 family)'
        tmpMachine['8d00'] = 'EM_TI_C6000 (The Texas Instruments TMS320C6000 DSP family)'
        tmpMachine['8e00'] = 'EM_TI_C2000 (The Texas Instruments TMS320C2000 DSP family)'
        tmpMachine['8f00'] = 'EM_TI_C5500 (The Texas Instruments TMS320C55x DSP family)'
        tmpMachine['a000'] = 'EM_MMDSP_PLUS (STMicroelectronics 64bit VLIW Data Signal Processor)'
        tmpMachine['a100'] = 'EM_CYPRESS_M8C (Cypress M8C microprocessor)'
        tmpMachine['a200'] = 'EM_R32C (Renesas R32C series microprocessors)'
	tmpMachine['a300'] = 'EM_TRIMEDIA (NXP Semiconductors TriMedia architecture family)'
        tmpMachine['a400'] = 'EM_HEXAGON (Qualcomm Hexagon processor)'
        tmpMachine['a500'] = 'EM_8051 (Intel 8051 and variants)'
        tmpMachine['a600'] = 'EM_STXP7X (STMicroelectronics STxP7x family)'
        tmpMachine['a700'] = 'EM_NDS32 (Andes Technology)'
        tmpMachine['7800'] = 'EM_ECOG1 (Cyan Technology eCOG1X family)'
        tmpMachine['a900'] = 'EM_ECOG1X (Cyan Technology eCOG1X family)'
        tmpMachine['aa00'] = 'EM_MAXQ30 (Dallas Semiconductor MAXQ30 Core Micro-controllers)'
        tmpMachine['ab00'] = 'EM_XIMO16 (New Japan Radio (NJR) 16-bit DSP Processor)'
        tmpMachine['ac00'] = 'EM_MANIK (M2000 Reconfigurable RISC Microprocessor)'
        tmpMachine['ad00'] = 'EM_CRAYNV2 (Cray Inc. NV2 vector architecture)'
        tmpMachine['ae00'] = 'EM_RX (Renesas RX family)'
        tmpMachine['af00'] = 'EM_METAG (Imagination Technologies META processor)'
        tmpMachine['b000'] = 'EM_MCST_ELBRUS (MCST Elbrus general purpose hardware architecture)'
        tmpMachine['b100'] = 'EM_ECOG16 (Cyan Technology eCOG16 family)'
        tmpMachine['b200'] = 'EM_CR16 (National Semiconductor CompactRISC CR16)'
        tmpMachine['b300'] = 'EM_ETPU (Freescale Extended Time Processing Unit)'
        tmpMachine['b400'] = 'EM_SLE9X (Infineon Technologies SLE9X core)'
        tmpMachine['b500'] = 'EM_L10M (Intel L10M)'
        tmpMachine['b600'] = 'EM_K10M (Intel K10M)'
        tmpMachine['b800'] = 'EM_AARCH64 (ARM AArch64)'
        tmpMachine['ba00'] = 'EM_AVR32 (Atmel Corporation 32-bit microprocessor family)'
        tmpMachine['bb00'] = 'EM_STM8 (STMicroeletronics STM8 8-bit microcontroller)'
        tmpMachine['bc00'] = 'EM_TILE64 (Tilera TILE64 multicore architecture family)' 
        tmpMachine['bd00'] = 'EM_TILEPRO (Tilera TILEPro multicore architecture family)'
        tmpMachine['bf00'] = 'EM_CUDA (NVIDIA CUDA architecture)'
        tmpMachine['c000'] = 'EM_TILEGX (Tilera TILE-Gx multicore architecture family)'
        tmpMachine['c100'] = 'EM_CLOUDSHIELD (CloudShield architecture family)'
        tmpMachine['c200'] = 'EM_COREA_1ST (KIPO-KAIST Core-A 1st generation processor family)'
        tmpMachine['c300'] = 'EM_COREA_2ND (KIPO-KAIST Core-A 2nd generation processor family)' 
        tmpMachine['c400'] = 'EM_ARRC_COMPACT2 (Synopsys ARCompact V2)'
        tmpMachine['c500'] = 'EM_OPEN8 (Open8 8-bit RISC soft processor core)'
        tmpMachine['c600'] = 'EM_RL78 (Renesas RL78 family)' 
        tmpMachine['c700'] = 'EM_VIDEOCORES (Broadcom VideoCore V processor)'
        tmpMachine['c800'] = 'EM_78KOR (Renesas 78KOR family)'
        tmpMachine['c900'] = 'EM_56800EX (Freescale 56800EX Digital Signal Controller (DSC))'
        tmpMachine['ca00'] = 'EM_BA1 (Beyond BA1 CPU architecture)'
        tmpMachine['cb00'] = 'EM_BA2 (Beyond BA2 CPU architecture)'
        tmpMachine['cc00'] = 'EM_XCORE (XMOS xCORE processor family)'
        tmpMachine['cd00'] = 'EM_MCHP_PIC (  EM_MCHP_PIC = 204, // Microchip 8-bit PIC(r) family)'
        tmpMachine['ce00'] = 'EM_INTEL205 (Reserved by Intel)'
        tmpMachine['cf00'] = 'EM_INTEL206 (Reserved by Intel)'
        tmpMachine['d000'] = 'EM_INTEL207 (Reserved by Intel)'
        tmpMachine['d100'] = 'EM_INTEL208 (Reserved by Intel)'
        tmpMachine['d200'] = 'EM_INTEL209 (Reserved by Intel)'
        tmpMachine['d300'] = 'EM_KM32 (KM211 KM32 32-bit processor)'
        tmpMachine['d400'] = 'EM_KMX32 (KM211 KMX32 32-bit processor)'
        tmpMachine['d500'] = 'EM_KMX16 (KM211 KMX16 16-bit processor)'
        tmpMachine['d600'] = 'EM_KMX8 (KM211 KMX8 8-bit processor)'
        tmpMachine['d700'] = 'EM_KVARC (KM211 KVARC processor)'
        tmpMachine['d800'] = 'EM_CDP (Paneve CDP architecture family)'
        tmpMachine['d900'] = 'EM_COGE (Cognitive Smart Memory Processor)' 
        tmpMachine['da00'] = 'EM_COOL (iCelero CoolEngine)'
        tmpMachine['db00'] = 'EM_NOORC (Nanoradio Optimized RISC)'
        tmpMachine['dc00'] = 'EM_CSR_KALIMBA (CSR Kalimba architecture family)'
        tmpMachine['e000'] = 'EM_AMD_GPU (AMD GPU architecture)'
        tmpMachine['f300'] = 'EM_RISCV (RISC-V)'
        tmpMachine['f400'] = 'EM_LANAI (Lanai 32-bit processor)'
        tmpMachine['f700'] = 'EM_BPF (Linux kernel bpf virtual machine)'
	
	print "\tMachine:\t"+tmpMachine[emachine]
	print "\tVersion:\t\t"+eversion
#Add check for endianess (i.e. if it is already big-endian))
	print "\tEntry Point Address:\t"+ change_endianess(eentry)
	print "\tProgram Header offset:\t"+change_endianess(ephoff)
	print "\tSection Header offset:\t"+change_endianess(eshoff)
	print "\tFlags:\t"+change_endianess(eflags)
	print "\tELF Header Size:\t"+change_endianess(ehsize)
	print "\tProgram Header Entry Size:\t"+change_endianess(ephentsize)
	print "\tProgram Header Entries:\t"+change_endianess(ephentsize)
	print "\tSection Header Entry Size:\t"+change_endianess(eshentsize)
	print "\tSection Header Entries:\t"+change_endianess(eshnum)
	print "\tSection name string table's index in Section Header: "+change_endianess(eshstrndx)


if len(sys.argv) < 2:
	print "Usage: "+sys.argv[0] + " <elf_file>"
	exit(1)

file = open(sys.argv[1], 'rb')

hexFile = binascii.hexlify(file.read())

if hexFile[0:8] != '7f454c46':
	print "\nPlease supply an ELF: \""+ sys.argv[1] + "\" is not an ELF file."
	print exit(1)

print "ELF reader by metantz\n"

print_ELF_Header(hexFile)

