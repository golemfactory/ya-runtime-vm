use raw_cpuid::CpuId;
use serde::export::TryFrom;

pub struct CpuInfo {
    pub model: CpuModel,
    pub capabilities: Vec<String>,
}

impl CpuInfo {
    pub fn try_new() -> anyhow::Result<CpuInfo> {
        let info = raw_cpuid::CpuId::new();
        let model = CpuModel::try_from(&info)?;
        let capabilities = cpu_features(&info)?;

        Ok(CpuInfo {
            model,
            capabilities,
        })
    }
}

pub struct CpuModel {
    pub vendor: String,
    pub stepping: u8,
    pub family: u16,
    pub model: u16,
}

impl<'a> TryFrom<&'a CpuId> for CpuModel {
    type Error = anyhow::Error;

    fn try_from(info: &'a CpuId) -> Result<Self, Self::Error> {
        let vendor = info
            .get_vendor_info()
            .ok_or_else(|| anyhow::anyhow!("Unable to read CPU vendor info"))?;
        let features = info
            .get_feature_info()
            .ok_or_else(|| anyhow::anyhow!("Unable to read CPU features"))?;

        Ok(CpuModel {
            vendor: vendor.to_string(),
            stepping: features.stepping_id(),
            family: (features.extended_family_id() as u16) + (features.family_id() as u16),
            model: ((features.extended_model_id() as u16) << 4) + (features.model_id() as u16),
        })
    }
}

macro_rules! flags {
    ($cpu_info:ident, $(($has:ident, $lit:tt)),*) => {{
        let mut results = Vec::new();
        $(if ($cpu_info.$has()) {
            results.push(stringify!($lit).to_lowercase());
        })*
        results
    }}
}

fn cpu_features(info: &CpuId) -> anyhow::Result<Vec<String>> {
    let features = info
        .get_feature_info()
        .ok_or_else(|| anyhow::anyhow!("Unable to read CPU features"))?;
    let ext_features = info
        .get_extended_feature_info()
        .ok_or_else(|| anyhow::anyhow!("Unable to read extended CPU features"))?;

    let mut capabilities = flags!(
        features,
        (has_sse3, SSE3),
        (has_pclmulqdq, PCLMULQDQ),
        (has_ds_area, DTES64),
        (has_monitor_mwait, MONITOR),
        (has_cpl, DSCPL),
        (has_vmx, VMX),
        (has_smx, SMX),
        (has_eist, EIST),
        (has_tm2, TM2),
        (has_ssse3, SSSE3),
        (has_cnxtid, CNXTID),
        (has_fma, FMA),
        (has_cmpxchg16b, CMPXCHG16B),
        (has_pdcm, PDCM),
        (has_pcid, PCID),
        (has_dca, DCA),
        (has_sse41, SSE41),
        (has_sse42, SSE42),
        (has_x2apic, X2APIC),
        (has_movbe, MOVBE),
        (has_popcnt, POPCNT),
        (has_tsc_deadline, TSC_DEADLINE),
        (has_aesni, AESNI),
        (has_xsave, XSAVE),
        (has_oxsave, OSXSAVE),
        (has_avx, AVX),
        (has_f16c, F16C),
        (has_rdrand, RDRAND),
        (has_hypervisor, HYPERVISOR),
        (has_fpu, FPU),
        (has_vme, VME),
        (has_de, DE),
        (has_pse, PSE),
        (has_tsc, TSC),
        (has_msr, MSR),
        (has_pae, PAE),
        (has_mce, MCE),
        (has_cmpxchg8b, CX8),
        (has_apic, APIC),
        (has_sysenter_sysexit, SEP),
        (has_mtrr, MTRR),
        (has_pge, PGE),
        (has_mca, MCA),
        (has_cmov, CMOV),
        (has_pat, PAT),
        (has_pse36, PSE36),
        (has_psn, PSN),
        (has_clflush, CLFSH),
        (has_ds, DS),
        (has_acpi, ACPI),
        (has_mmx, MMX),
        (has_fxsave_fxstor, FXSR),
        (has_sse, SSE),
        (has_sse2, SSE2),
        (has_ss, SS),
        (has_htt, HTT),
        (has_tm, TM),
        (has_pbe, PBE)
    );
    capabilities.extend(
        flags!(
            ext_features,
            (has_fsgsbase, FSGSBASE),
            (has_tsc_adjust_msr, ADJUST_MSR),
            (has_fdp, FDP),
            (has_smep, SMEP),
            (has_rep_movsb_stosb, REP_MOVSB_STOSB),
            (has_invpcid, INVPCID),
            (has_rdtm, RDTM),
            (has_fpu_cs_ds_deprecated, DEPRECATE_FPU_CS_DS),
            (has_mpx, MPX),
            (has_rdta, RDTA),
            (has_rdseed, RDSEED),
            (has_rdseet, RDSEED),
            (has_adx, ADX),
            (has_smap, SMAP),
            (has_clflushopt, CLFLUSHOPT),
            (has_processor_trace, PROCESSOR_TRACE),
            (has_sha, SHA),
            (has_sgx, SGX),
            (has_avx512f, AVX512F),
            (has_avx512dq, AVX512DQ),
            (has_avx512_ifma, AVX512_IFMA),
            (has_avx512pf, AVX512PF),
            (has_avx512er, AVX512ER),
            (has_avx512cd, AVX512CD),
            (has_avx512bw, AVX512BW),
            (has_avx512vl, AVX512VL),
            (has_prefetchwt1, PREFETCHWT1),
            (has_umip, UMIP),
            (has_pku, PKU),
            (has_ospke, OSPKE),
            (has_rdpid, RDPID),
            (has_sgx_lc, SGX_LC)
        )
        .into_iter(),
    );

    Ok(capabilities)
}
