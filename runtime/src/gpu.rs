use crate::detect_pci;

pub struct GpuInfo {
    pub name: String,
}

impl GpuInfo {
    pub fn try_new() -> anyhow::Result<GpuInfo> {
        let mut gpu_name = String::from("None");
        let nvidia_vendor_id = String::from("10de");

        match std::env::var("GPU_PCI") {
            Ok(val) => {
                if val != "no" {
                    let gpu_pci_id = String::from(val);
                    gpu_name = detect_pci::detect_pci(gpu_pci_id, nvidia_vendor_id);
                }
            }
            Err(_e) => {}
        }

        Ok(GpuInfo {
            name: gpu_name.to_string(),
        })
    }
}
