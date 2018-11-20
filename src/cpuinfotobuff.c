/******************************************************************************
 * cpuinfotobuff.c
 *
 * Outputs cpuid-dump, cpu-info, cache-info, isa-info to a buffer
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64
#include <x86/cpuid.h>
#endif

#include <cpuinfo.h>

// ---------------------------------------------------------------------------
//
// From cpuid-dump.c
//

#if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64
static int snreport_cpuid(char * _buff, size_t _buffLen,
                         struct cpuid_regs regs, uint32_t eax)
{
    return(snprintf(_buff, _buffLen,
        "CPUID %08"PRIX32": %08"PRIX32"-%08"PRIX32"-%08"PRIX32"-%08"PRIX32"\n",
        eax, regs.eax, regs.ebx, regs.ecx, regs.edx));
}

static int snreport_cpuidex(char * _buff, size_t _buffLen,
                           struct cpuid_regs regs, uint32_t eax, uint32_t ecx)
{
    return(snprintf(_buff, _buffLen, "CPUID %08"PRIX32": %08"PRIX32"-%08"PRIX32"-%08"PRIX32"-%08"PRIX32" [SL %02"PRIX32"]\n",
                    eax, regs.eax, regs.ebx, regs.ecx, regs.edx, ecx));
}

static int snreport_cpuid_vendor(char * _buff, size_t _buffLen,
                                struct cpuid_regs regs, uint32_t eax)
{
	if (regs.ebx | regs.ecx | regs.edx) {
		char vendor_id[12];
		memcpy(&vendor_id[0], &regs.ebx, sizeof(regs.ebx));
		memcpy(&vendor_id[4], &regs.edx, sizeof(regs.edx));
		memcpy(&vendor_id[8], &regs.ecx, sizeof(regs.ecx));
		return(snprintf(_buff, _buffLen, "CPUID %08"PRIX32": %08"PRIX32"-%08"PRIX32"-%08"PRIX32"-%08"PRIX32" [%.12s]\n",
                                eax, regs.eax, regs.ebx, regs.ecx, regs.edx, vendor_id));
	} else {
            return(snreport_cpuid(_buff, _buffLen, regs, eax));
	}
}

static int snreport_cpuid_brand_string(char * _buff, size_t _buffLen,
                                      struct cpuid_regs regs, uint32_t eax)
{
	char brand_string[16];
	memcpy(&brand_string[0], &regs.eax, sizeof(regs.eax));
	memcpy(&brand_string[4], &regs.ebx, sizeof(regs.ebx));
	memcpy(&brand_string[8], &regs.ecx, sizeof(regs.ecx));
	memcpy(&brand_string[12], &regs.edx, sizeof(regs.edx));
	return(snprintf(_buff, _buffLen, "CPUID %08"PRIX32": %08"PRIX32"-%08"PRIX32"-%08"PRIX32"-%08"PRIX32" [%.16s]\n",
                        eax, regs.eax, regs.ebx, regs.ecx, regs.edx, brand_string));
}

#endif // of if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64

// ---------------------------------------------------------------------------
//
// From cpuid-info.c
//

static const char* vendor_to_string(enum cpuinfo_vendor vendor) {
	switch (vendor) {
		case cpuinfo_vendor_unknown:
			return "unknown";
		case cpuinfo_vendor_intel:
			return "Intel";
		case cpuinfo_vendor_amd:
			return "AMD";
		case cpuinfo_vendor_arm:
			return "ARM";
		case cpuinfo_vendor_qualcomm:
			return "Qualcomm";
		case cpuinfo_vendor_apple:
			return "Apple";
		case cpuinfo_vendor_samsung:
			return "Samsung";
		case cpuinfo_vendor_nvidia:
			return "Nvidia";
		case cpuinfo_vendor_mips:
			return "MIPS";
		case cpuinfo_vendor_ibm:
			return "IBM";
		case cpuinfo_vendor_ingenic:
			return "Ingenic";
		case cpuinfo_vendor_via:
			return "VIA";
		case cpuinfo_vendor_cavium:
			return "Cavium";
		case cpuinfo_vendor_broadcom:
			return "Broadcom";
		case cpuinfo_vendor_apm:
			return "Applied Micro";
		default:
			return NULL;
	}
}

static const char* uarch_to_string(enum cpuinfo_uarch uarch) {
	switch (uarch) {
		case cpuinfo_uarch_unknown:
			return "unknown";
		case cpuinfo_uarch_p5:
			return "P5";
		case cpuinfo_uarch_quark:
			return "Quark";
		case cpuinfo_uarch_p6:
			return "P6";
		case cpuinfo_uarch_dothan:
			return "Dothan";
		case cpuinfo_uarch_yonah:
			return "Yonah";
		case cpuinfo_uarch_conroe:
			return "Conroe";
		case cpuinfo_uarch_penryn:
			return "Penryn";
		case cpuinfo_uarch_nehalem:
			return "Nehalem";
		case cpuinfo_uarch_sandy_bridge:
			return "Sandy Bridge";
		case cpuinfo_uarch_ivy_bridge:
			return "Ivy Bridge";
		case cpuinfo_uarch_haswell:
			return "Haswell";
		case cpuinfo_uarch_broadwell:
			return "Broadwell";
		case cpuinfo_uarch_sky_lake:
			return "Sky Lake";
		case cpuinfo_uarch_kaby_lake:
			return "Kaby Lake";
		case cpuinfo_uarch_willamette:
			return "Willamette";
		case cpuinfo_uarch_prescott:
			return "Prescott";
		case cpuinfo_uarch_bonnell:
			return "Bonnell";
		case cpuinfo_uarch_saltwell:
			return "Saltwell";
		case cpuinfo_uarch_silvermont:
			return "Silvermont";
		case cpuinfo_uarch_airmont:
			return "Airmont";
		case cpuinfo_uarch_knights_ferry:
			return "Knights Ferry";
		case cpuinfo_uarch_knights_corner:
			return "Knights Corner";
		case cpuinfo_uarch_knights_landing:
			return "Knights Landing";
		case cpuinfo_uarch_knights_hill:
			return "Knights Hill";
		case cpuinfo_uarch_knights_mill:
			return "Knights Mill";
		case cpuinfo_uarch_k5:
			return "K5";
		case cpuinfo_uarch_k6:
			return "K6";
		case cpuinfo_uarch_k7:
			return "K7";
		case cpuinfo_uarch_k8:
			return "K8";
		case cpuinfo_uarch_k10:
			return "K10";
		case cpuinfo_uarch_bulldozer:
			return "Bulldozer";
		case cpuinfo_uarch_piledriver:
			return "Piledriver";
		case cpuinfo_uarch_steamroller:
			return "Steamroller";
		case cpuinfo_uarch_excavator:
			return "Excavator";
		case cpuinfo_uarch_zen:
			return "Zen";
		case cpuinfo_uarch_geode:
			return "Geode";
		case cpuinfo_uarch_bobcat:
			return "Bobcat";
		case cpuinfo_uarch_jaguar:
			return "Jaguar";
		case cpuinfo_uarch_puma:
			return "Puma";
		case cpuinfo_uarch_xscale:
			return "XScale";
		case cpuinfo_uarch_arm7:
			return "ARM7";
		case cpuinfo_uarch_arm9:
			return "ARM9";
		case cpuinfo_uarch_arm11:
			return "ARM11";
		case cpuinfo_uarch_cortex_a5:
			return "Cortex-A5";
		case cpuinfo_uarch_cortex_a7:
			return "Cortex-A7";
		case cpuinfo_uarch_cortex_a8:
			return "Cortex-A8";
		case cpuinfo_uarch_cortex_a9:
			return "Cortex-A9";
		case cpuinfo_uarch_cortex_a12:
			return "Cortex-A12";
		case cpuinfo_uarch_cortex_a15:
			return "Cortex-A15";
		case cpuinfo_uarch_cortex_a17:
			return "Cortex-A17";
		case cpuinfo_uarch_cortex_a32:
			return "Cortex-A32";
		case cpuinfo_uarch_cortex_a35:
			return "Cortex-A35";
		case cpuinfo_uarch_cortex_a53:
			return "Cortex-A53";
		case cpuinfo_uarch_cortex_a55:
			return "Cortex-A55";
		case cpuinfo_uarch_cortex_a57:
			return "Cortex-A57";
		case cpuinfo_uarch_cortex_a72:
			return "Cortex-A72";
		case cpuinfo_uarch_cortex_a73:
			return "Cortex-A73";
		case cpuinfo_uarch_cortex_a75:
			return "Cortex-A75";
		case cpuinfo_uarch_cortex_a76:
			return "Cortex-A76";
		case cpuinfo_uarch_scorpion:
			return "Scorpion";
		case cpuinfo_uarch_krait:
			return "Krait";
		case cpuinfo_uarch_kryo:
			return "Kryo";
		case cpuinfo_uarch_falkor:
			return "Falkor";
		case cpuinfo_uarch_saphira:
			return "Saphira";
		case cpuinfo_uarch_denver:
			return "Denver";
		case cpuinfo_uarch_denver2:
			return "Denver 2";
		case cpuinfo_uarch_carmel:
			return "Carmel";
		case cpuinfo_uarch_mongoose_m1:
			return "Mongoose M1";
		case cpuinfo_uarch_mongoose_m2:
			return "Mongoose M2";
		case cpuinfo_uarch_meerkat_m3:
			return "Meerkat M3";
		case cpuinfo_uarch_swift:
			return "Swift";
		case cpuinfo_uarch_cyclone:
			return "Cyclone";
		case cpuinfo_uarch_typhoon:
			return "Typhoon";
		case cpuinfo_uarch_twister:
			return "Twister";
		case cpuinfo_uarch_hurricane:
			return "Hurricane";
		case cpuinfo_uarch_thunderx:
			return "ThunderX";
		case cpuinfo_uarch_thunderx2:
			return "ThunderX2";
		case cpuinfo_uarch_pj4:
			return "PJ4";
		case cpuinfo_uarch_brahma_b15:
			return "Brahma B15";
		case cpuinfo_uarch_brahma_b53:
			return "Brahma B53";
		case cpuinfo_uarch_xgene:
			return "X-Gene";
		default:
			return NULL;
	}
}

// ---------------------------------------------------------------------------
//
// From cache-info.c
//


static int snreport_cache(char * _buff, size_t _buffLen,
                          uint32_t count, const struct cpuinfo_cache* cache,
                          uint32_t level, const char* nonunified_type)
{
    unsigned int buff_used = 0;
    int pf_res = -1;

    const char* type = (cache->flags & CPUINFO_CACHE_UNIFIED) ? "unified" : nonunified_type;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "L%"PRIu32" %s cache: ", level, type);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

    uint32_t size = cache->size;
    const char* units = "bytes";
    if (size % UINT32_C(1048576) == 0) {
        size /= UINT32_C(1048576);
        units = "MB";
    } else if (size % UINT32_C(1024) == 0) {
        size /= UINT32_C(1024);
        units = "KB";
    }
    if (count != 1) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "%"PRIu32" x ", count);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    }
    if (level == 1) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "%"PRIu32" %s, ", size, units);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    } else {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "%"PRIu32" %s (%s), ", size, units, (cache->flags & CPUINFO_CACHE_INCLUSIVE) ? "inclusive" : "exclusive");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    }

    if (cache->associativity * cache->line_size == cache->size) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "fully associative");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    } else {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "%"PRIu32"-way set associative", cache->associativity);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    }
    if (cache->sets != 0) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, " (%"PRIu32" sets", cache->sets);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
        if (cache->partitions != 1) {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", %"PRIu32" partitions", cache->partitions);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
        if (cache->flags & CPUINFO_CACHE_COMPLEX_INDEXING) {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", complex indexing), ");
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        } else {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "), ");
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
    }

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "%"PRIu32" byte lines", cache->line_size);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    if (cache->processor_count != 0) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", shared by %"PRIu32" processors\n", cache->processor_count);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    } else {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\n");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    }
    
    return(buff_used);
}

// ---------------------------------------------------------------------------
//
// From isa-info.c
//


static int snreport_isa(char * _buff, size_t _buffLen)
{
    unsigned int buff_used = 0;
    int pf_res = -1;
    
#if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Scalar instructions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#if CPUINFO_ARCH_X86
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tx87 FPU: %s\n", cpuinfo_has_x86_fpu() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCMOV: %s\n", cpuinfo_has_x86_cmov() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#endif
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tLAHF/SAHF: %s\n", cpuinfo_has_x86_lahf_sahf() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tLZCNT: %s\n", cpuinfo_has_x86_lzcnt() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPOPCNT: %s\n", cpuinfo_has_x86_popcnt() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tTBM: %s\n", cpuinfo_has_x86_tbm() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tBMI: %s\n", cpuinfo_has_x86_bmi() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tBMI2: %s\n", cpuinfo_has_x86_bmi2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tADCX/ADOX: %s\n", cpuinfo_has_x86_adx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Memory instructions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMOVBE: %s\n", cpuinfo_has_x86_movbe() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPREFETCH: %s\n", cpuinfo_has_x86_prefetch() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPREFETCHW: %s\n", cpuinfo_has_x86_prefetchw() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPREFETCHWT1: %s\n", cpuinfo_has_x86_prefetchwt1() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCLZERO: %s\n", cpuinfo_has_x86_clzero() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "SIMD extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMMX: %s\n", cpuinfo_has_x86_mmx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMMX+: %s\n", cpuinfo_has_x86_mmx_plus() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t3dnow!: %s\n", cpuinfo_has_x86_3dnow() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t3dnow!+: %s\n", cpuinfo_has_x86_3dnow_plus() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t3dnow! Geode: %s\n", cpuinfo_has_x86_3dnow_geode() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tDAZ: %s\n", cpuinfo_has_x86_daz() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE: %s\n", cpuinfo_has_x86_sse() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE2: %s\n", cpuinfo_has_x86_sse2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE3: %s\n", cpuinfo_has_x86_sse3() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSSE3: %s\n", cpuinfo_has_x86_ssse3() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE4.1: %s\n", cpuinfo_has_x86_sse4_1() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE4.2: %s\n", cpuinfo_has_x86_sse4_2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSSE4a: %s\n", cpuinfo_has_x86_sse4a() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMisaligned SSE: %s\n", cpuinfo_has_x86_misaligned_sse() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX: %s\n", cpuinfo_has_x86_avx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tFMA3: %s\n", cpuinfo_has_x86_fma3() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tFMA4: %s\n", cpuinfo_has_x86_fma4() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tXOP: %s\n", cpuinfo_has_x86_xop() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tF16C: %s\n", cpuinfo_has_x86_f16c() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX2: %s\n", cpuinfo_has_x86_avx2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512F: %s\n", cpuinfo_has_x86_avx512f() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512PF: %s\n", cpuinfo_has_x86_avx512pf() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512ER: %s\n", cpuinfo_has_x86_avx512er() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512CD: %s\n", cpuinfo_has_x86_avx512cd() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512DQ: %s\n", cpuinfo_has_x86_avx512dq() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512BW: %s\n", cpuinfo_has_x86_avx512bw() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512VL: %s\n", cpuinfo_has_x86_avx512vl() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512IFMA: %s\n", cpuinfo_has_x86_avx512ifma() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512VBMI: %s\n", cpuinfo_has_x86_avx512vbmi() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512VBMI2: %s\n", cpuinfo_has_x86_avx512vbmi2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512BITALG: %s\n", cpuinfo_has_x86_avx512bitalg() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512VPOPCNTDQ: %s\n", cpuinfo_has_x86_avx512vpopcntdq() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512VNNI: %s\n", cpuinfo_has_x86_avx512vnni() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512_4VNNIW: %s\n", cpuinfo_has_x86_avx512_4vnniw() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAVX512_4FMAPS: %s\n", cpuinfo_has_x86_avx512_4fmaps() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Multi-threading extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMONITOR/MWAIT: %s\n", cpuinfo_has_x86_mwait() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMONITORX/MWAITX: %s\n", cpuinfo_has_x86_mwaitx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#if CPUINFO_ARCH_X86
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCMPXCHG8B: %s\n", cpuinfo_has_x86_cmpxchg8b() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#endif
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCMPXCHG16B: %s\n", cpuinfo_has_x86_cmpxchg16b() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tHLE: %s\n", cpuinfo_has_x86_hle() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRTM: %s\n", cpuinfo_has_x86_rtm() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tXTEST: %s\n", cpuinfo_has_x86_xtest() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRDPID: %s\n", cpuinfo_has_x86_rdpid() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Cryptography extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAES: %s\n", cpuinfo_has_x86_aes() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVAES: %s\n", cpuinfo_has_x86_vaes() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPCLMULQDQ: %s\n", cpuinfo_has_x86_pclmulqdq() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVPCLMULQDQ: %s\n", cpuinfo_has_x86_vpclmulqdq() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tGFNI: %s\n", cpuinfo_has_x86_gfni() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRDRAND: %s\n", cpuinfo_has_x86_rdrand() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRDSEED: %s\n", cpuinfo_has_x86_rdseed() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSHA: %s\n", cpuinfo_has_x86_sha() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Profiling instructions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#if CPUINFO_ARCH_X86
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRDTSC: %s\n", cpuinfo_has_x86_rdtsc() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#endif
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tRDTSCP: %s\n", cpuinfo_has_x86_rdtscp() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tMPX: %s\n", cpuinfo_has_x86_mpx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;


    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "System instructions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCLWB: %s\n", cpuinfo_has_x86_clwb() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tFXSAVE/FXSTOR: %s\n", cpuinfo_has_x86_fxsave() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tXSAVE/XSTOR: %s\n", cpuinfo_has_x86_xsave() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

#endif /* CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64 */

#if CPUINFO_ARCH_ARM
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Instruction sets:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tThumb: %s\n", cpuinfo_has_arm_thumb() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tThumb 2: %s\n", cpuinfo_has_arm_thumb2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARMv5E: %s\n", cpuinfo_has_arm_v5e() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARMv6: %s\n", cpuinfo_has_arm_v6() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARMv6-K: %s\n", cpuinfo_has_arm_v6k() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARMv7: %s\n", cpuinfo_has_arm_v7() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARMv7 MP: %s\n", cpuinfo_has_arm_v7mp() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tIDIV: %s\n", cpuinfo_has_arm_idiv() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Floating-Point support:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv2: %s\n", cpuinfo_has_arm_vfpv2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv3: %s\n", cpuinfo_has_arm_vfpv3() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv3+D32: %s\n", cpuinfo_has_arm_vfpv3_d32() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv3+FP16: %s\n", cpuinfo_has_arm_vfpv3_fp16() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv3+FP16+D32: %s\n", cpuinfo_has_arm_vfpv3_fp16_d32() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv4: %s\n", cpuinfo_has_arm_vfpv4() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVFPv4+D32: %s\n", cpuinfo_has_arm_vfpv4_d32() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tVJCVT: %s\n", cpuinfo_has_arm_jscvt() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "SIMD extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tWMMX: %s\n", cpuinfo_has_arm_wmmx() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tWMMX 2: %s\n", cpuinfo_has_arm_wmmx2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON: %s\n", cpuinfo_has_arm_neon() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON-FP16: %s\n", cpuinfo_has_arm_neon_fp16() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON-FMA: %s\n", cpuinfo_has_arm_neon_fma() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON VQRDMLAH/VQRDMLSH: %s\n", cpuinfo_has_arm_neon_rdm() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON FP16 arithmetics: %s\n", cpuinfo_has_arm_fp16_arith() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tNEON complex: %s\n", cpuinfo_has_arm_fcma() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Cryptography extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAES: %s\n", cpuinfo_has_arm_aes() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSHA1: %s\n", cpuinfo_has_arm_sha1() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSHA2: %s\n", cpuinfo_has_arm_sha2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPMULL: %s\n", cpuinfo_has_arm_pmull() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCRC32: %s\n", cpuinfo_has_arm_crc32() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#endif /* CPUINFO_ARCH_ARM */
#if CPUINFO_ARCH_ARM64
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Instruction sets:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARM v8.1 atomics: %s\n", cpuinfo_has_arm_atomics() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARM v8.1 SQRDMLxH: %s\n", cpuinfo_has_arm_neon_rdm() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARM v8.2 FP16 arithmetics: %s\n", cpuinfo_has_arm_fp16_arith() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARM v8.3 JS conversion: %s\n", cpuinfo_has_arm_jscvt() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tARM v8.3 complex: %s\n", cpuinfo_has_arm_fcma() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;

    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Cryptography extensions:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tAES: %s\n", cpuinfo_has_arm_aes() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSHA1: %s\n", cpuinfo_has_arm_sha1() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tSHA2: %s\n", cpuinfo_has_arm_sha2() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tPMULL: %s\n", cpuinfo_has_arm_pmull() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\tCRC32: %s\n", cpuinfo_has_arm_crc32() ? "yes" : "no");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
#endif

    return(buff_used);
}

// ---------------------------------------------------------------------------

// From cpu-info.c
    
static int snreport_cpu_info(char * _buff, size_t _buffLen)
{
    unsigned int buff_used = 0;
    int pf_res = -1;

    #ifdef __ANDROID__
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "SoC name: %s\n", cpuinfo_get_package(0)->name);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "GPU name: %s\n", cpuinfo_get_package(0)->gpu_name);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    #else
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Packages:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    for (uint32_t i = 0; i < cpuinfo_get_packages_count(); i++) {
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t%"PRIu32": %s\n", i, cpuinfo_get_package(i)->name);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
    }
    #endif
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Cores:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    for (uint32_t i = 0; i < cpuinfo_get_cores_count(); i++) {
        const struct cpuinfo_core* core = cpuinfo_get_core(i);
        if (core->processor_count == 1) {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t%"PRIu32": 1 processor (%"PRIu32")", i, core->processor_start);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        } else {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t%"PRIu32": %"PRIu32" processors (%"PRIu32"-%"PRIu32")",
                   i, core->processor_count, core->processor_start, core->processor_start + core->processor_count - 1);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
        const char* vendor_string = vendor_to_string(core->vendor);
        const char* uarch_string = uarch_to_string(core->uarch);
        if (vendor_string == NULL) {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", vendor 0x%08"PRIx32" uarch 0x%08"PRIx32"\n",
                   (uint32_t) core->vendor, (uint32_t) core->uarch);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
        else if (uarch_string == NULL) {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", %s uarch 0x%08"PRIx32"\n",
                   vendor_string, (uint32_t) core->uarch);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
        else {
            pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, ", %s %s\n", vendor_string, uarch_string);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
                return(buff_used+pf_res);
            buff_used += pf_res;
        }
    }
    pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "Logical processors:\n");
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
        return(buff_used+pf_res);
    buff_used += pf_res;
    for (uint32_t i = 0; i < cpuinfo_get_processors_count(); i++) {
        const struct cpuinfo_processor* processor = cpuinfo_get_processor(i);
        #if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t%"PRIu32": APIC ID 0x%08"PRIx32"\n", i, processor->apic_id);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
        #else
        pf_res = snprintf(_buff+buff_used, _buffLen-buff_used, "\t%"PRIu32"\n", i);
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
            return(buff_used+pf_res);
        buff_used += pf_res;
        #endif
    }
    
    return(buff_used);
}

// ---------------------------------------------------------------------------
// main entry point for this file

int cpuinfotobuff(char * _buff, size_t _buffLen)
{
    if (!_buff)
    {
        errno = EINVAL;
        return(-1);
    }
    if (_buffLen < 1024)
    {
        errno = ENOBUFS;
        return(-1);
    }

    _buff[0] = 0;

    if (!cpuinfo_initialize())
    {
        errno = EPERM;
        return(-1);
    }

    unsigned int buff_used = 0;
    int pf_res = -1;


    // From cpuid-dump.c

    #if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64

    const uint32_t max_base_index = cpuid(0).eax;
    uint32_t max_structured_index = 0, max_trace_index = 0, max_socid_index =0;
    bool has_sgx = false;
    for (uint32_t eax = 0; eax <= max_base_index; eax++)
    {
        switch (eax)
        {
        case UINT32_C(0x00000000):
            pf_res = snreport_cpuid_vendor(_buff+buff_used, _buffLen-buff_used, cpuid(eax), eax);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
            break;
        case UINT32_C(0x00000004):
            for (uint32_t ecx = 0; ; ecx++)
            {
                const struct cpuid_regs regs = cpuidex(eax, ecx);
                if ((regs.eax & UINT32_C(0x1F)) == 0)
                    break;
                pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);            }
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
            break;
        case UINT32_C(0x00000007):
            for (uint32_t ecx = 0; ecx <= max_structured_index; ecx++)
            {
                const struct cpuid_regs regs = cpuidex(eax, ecx);
                if (ecx == 0)
                {
                    max_structured_index = regs.eax;
                    has_sgx = !!(regs.ebx & UINT32_C(0x00000004));
                }
                pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);
                if (pf_res < 0)
                    return(pf_res);
                if (pf_res >= (_buffLen-buff_used))
                {
                    errno = ENOBUFS;
                    return(-2);
                }
                buff_used += pf_res;
            }
            break;
        case UINT32_C(0x0000000B):
            for (uint32_t ecx = 0; ; ecx++)
            {
                const struct cpuid_regs regs = cpuidex(eax, ecx);
                if ((regs.ecx & UINT32_C(0x0000FF00)) == 0)
                    break;
                pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);
                if (pf_res < 0)
                    return(pf_res);
                if (pf_res >= (_buffLen-buff_used))
                {
                    errno = ENOBUFS;
                    return(-2);
                }
                buff_used += pf_res;
            }
            break;
        case UINT32_C(0x00000012):
            if (has_sgx)
            {
                for (uint32_t ecx = 0; ; ecx++)
                {
                    const struct cpuid_regs regs = cpuidex(eax, ecx);
                    if (ecx >= 2 && (regs.eax & UINT32_C(0x0000000F)) == 0)
                        break;
                    pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);
                    if (pf_res < 0)
                        return(pf_res);
                    if (pf_res >= (_buffLen-buff_used))
                    {
                        errno = ENOBUFS;
                        return(-2);
                    }
                    buff_used += pf_res;
                }
            }
            break;
        case UINT32_C(0x00000014):
            for (uint32_t ecx = 0; ecx <= max_trace_index; ecx++)
            {
                const struct cpuid_regs regs = cpuidex(eax, ecx);
                if (ecx == 0)
                    max_trace_index = regs.eax;
                pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);
                if (pf_res < 0)
                    return(pf_res);
                if (pf_res >= (_buffLen-buff_used))
                {
                    errno = ENOBUFS;
                    return(-2);
                }
                buff_used += pf_res;
            }
            break;
        case UINT32_C(0x00000017):
            for (uint32_t ecx = 0; ecx <= max_socid_index; ecx++)
            {
                const struct cpuid_regs regs = cpuidex(eax, ecx);
                if (ecx == 0)
                    max_socid_index = regs.eax;
                pf_res = snreport_cpuidex(_buff+buff_used, _buffLen-buff_used, regs, eax, ecx);
                if (pf_res < 0)
                    return(pf_res);
                if (pf_res >= (_buffLen-buff_used))
                {
                    errno = ENOBUFS;
                    return(-2);
                }
                buff_used += pf_res;
            }
            break;
        default:
            pf_res = snreport_cpuid(_buff+buff_used, _buffLen-buff_used, cpuidex(eax, 0), eax);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
            break;
        }
    }

    const uint32_t max_extended_index = cpuid(UINT32_C(0x80000000)).eax;
    for (uint32_t eax = UINT32_C(0x80000000); eax <= max_extended_index; eax++)
    {
        switch (eax)
        {
        case UINT32_C(0x80000000):
            pf_res = snreport_cpuid_vendor(_buff+buff_used, _buffLen-buff_used, cpuid(eax), eax);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
            break;
        case UINT32_C(0x80000002):
        case UINT32_C(0x80000003):
        case UINT32_C(0x80000004):
            pf_res = snreport_cpuid_brand_string(_buff+buff_used, _buffLen-buff_used, cpuid(eax), eax);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
            break;
        default:
            pf_res = snreport_cpuid(_buff+buff_used, _buffLen-buff_used, cpuidex(eax, 0), eax);
            if (pf_res < 0)
                return(pf_res);
            if (pf_res >= (_buffLen-buff_used))
            {
                errno = ENOBUFS;
                return(-2);
            }
            buff_used += pf_res;
        }
    }
    #endif // if CPUINFO_ARCH_X86 || CPUINFO_ARCH_X86_64

    // From cpu-info.c

    pf_res = snreport_cpu_info(_buff+buff_used, _buffLen-buff_used);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
    {
        errno = ENOBUFS;
        return(-2);
    }
    buff_used += pf_res;

    // From cache-info.c

    if (cpuinfo_get_l1i_caches_count() != 0 && (cpuinfo_get_l1i_cache(0)->flags & CPUINFO_CACHE_UNIFIED) == 0) {
        pf_res = snreport_cache(_buff+buff_used, _buffLen-buff_used, cpuinfo_get_l1i_caches_count(), cpuinfo_get_l1i_cache(0), 1, "instruction");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
        {
            errno = ENOBUFS;
            return(-2);
        }
        buff_used += pf_res;
    }
    if (cpuinfo_get_l1d_caches_count() != 0) {
        pf_res = snreport_cache(_buff+buff_used, _buffLen-buff_used, cpuinfo_get_l1d_caches_count(), cpuinfo_get_l1d_cache(0), 1, "data");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
        {
            errno = ENOBUFS;
            return(-2);
        }
        buff_used += pf_res;
    }
    if (cpuinfo_get_l2_caches_count() != 0) {
        pf_res = snreport_cache(_buff+buff_used, _buffLen-buff_used, cpuinfo_get_l2_caches_count(), cpuinfo_get_l2_cache(0), 2, "data");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
        {
            errno = ENOBUFS;
            return(-2);
        }
        buff_used += pf_res;
    }
    if (cpuinfo_get_l3_caches_count() != 0) {
        pf_res = snreport_cache(_buff+buff_used, _buffLen-buff_used, cpuinfo_get_l3_caches_count(), cpuinfo_get_l3_cache(0), 3, "data");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
        {
            errno = ENOBUFS;
            return(-2);
        }
        buff_used += pf_res;
    }
    if (cpuinfo_get_l4_caches_count() != 0) {
        pf_res = snreport_cache(_buff+buff_used, _buffLen-buff_used, cpuinfo_get_l4_caches_count(), cpuinfo_get_l4_cache(0), 4, "data");
        if (pf_res < 0)
            return(pf_res);
        if (pf_res >= (_buffLen-buff_used))
        {
            errno = ENOBUFS;
            return(-2);
        }
        buff_used += pf_res;
    }

    // From isa-info.c

    pf_res = snreport_isa(_buff+buff_used, _buffLen-buff_used);
    if (pf_res < 0)
        return(pf_res);
    if (pf_res >= (_buffLen-buff_used))
    {
        errno = ENOBUFS;
        return(-2);
    }
    buff_used += pf_res;

    return(0);
}


    
    
    

