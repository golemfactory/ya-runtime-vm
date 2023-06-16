use std::process::Command;

pub fn detect_pci(pci_id: String, vendor_id: String) -> String {
    let mut device_found = false;
    let mut device_name = "None";

    let cmd = Command::new("lspci")
        .arg("-vnn")
        .output()
        .expect("failed to execute process");

    let stdout = String::from_utf8_lossy(&cmd.stdout);
    let lines = stdout.split("\n");

    for line in lines {
        if line.starts_with(&pci_id) {
            let index_vid = line[..].find(&vendor_id);
            if !index_vid.is_none() {
                device_found = true;
                let index_start_vid = index_vid.unwrap();
                let index_start_pid =
                    index_start_vid + line[index_start_vid..].find(":").unwrap() + 1;
                let index_end_pid = index_start_pid + line[index_start_pid..].find("]").unwrap();
                let s_pid = &line[index_start_pid..index_end_pid];
                let vid = u16::from_str_radix(&vendor_id, 16).unwrap();
                let pid = u16::from_str_radix(s_pid, 16).unwrap();
                let device = pci_ids::Device::from_vid_pid(vid, pid).unwrap();
                device_name = pci_ids::Device::name(device);
            } else {
                break;
            }
        } else if device_found {
            if !line.find("Kernel driver in use").is_none() {
                let line_driver: Vec<&str> = line.split(":").collect();
                let driver = line_driver[1].trim_start();
                if driver != "vfio-pci" {
                    device_name = "None";
                }
                break;
            }
        }
    }

    device_name.to_string()
}
