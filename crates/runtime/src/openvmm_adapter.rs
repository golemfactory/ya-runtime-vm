use std::fs::{File, OpenOptions};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::Context;
use mesh::MeshPayload;
use net_backend::resolve::{ResolveEndpointParams, ResolvedEndpoint};
use net_backend_resources::mac_address::MacAddress;
use openvmm_defs::config::{
    ArchTopologyConfig, Config, LinuxDirectBootMode, LinuxIsolationConfig, LoadMode, MemoryConfig,
    NumaNode, NumaTopology, PcieDeviceConfig, PcieRootComplexConfig, ProcessorTopologyConfig,
    VpAssignment, X86TopologyConfig,
};
#[cfg(target_os = "linux")]
use openvmm_defs::config::{PcieMmioRangeConfig, PciePortConfig};
use virtio::resolve::{ResolvedVirtioDevice, VirtioResolveInput};
use vm_manifest_builder::{BaseChipsetType, MachineArch, VmManifestBuilder};
use vm_resource::kind::{DiskHandleKind, NetEndpointHandleKind, VirtioDeviceHandle};
use vm_resource::{
    AsyncResolveResource, IntoResource, ResolveResource, ResourceId, ResourceResolver,
    declare_static_async_resolver, declare_static_resolver,
};
use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::runtime_api::server::NetworkInterface;

use crate::deploy::Deployment;
use crate::net_socket::{
    SocketEndpoint, SocketMode, SocketRegistrationGuard, take_registered_endpoint,
};

extern crate openvmm_resources as _;

pub(crate) fn build_config(
    runtime_dir: &Path,
    work_dir: &Path,
    deployment: &Deployment,
    manager_vsock: virtio_resources::vsock::VirtioVsockHandle,
    vpn_remote: Option<&ya_runtime_sdk::server::ContainerEndpoint>,
    inet_remote: Option<&ya_runtime_sdk::server::ContainerEndpoint>,
    pci_device_ids: &[String],
) -> anyhow::Result<(
    Config,
    Option<ya_runtime_sdk::server::ContainerEndpoint>,
    Option<ya_runtime_sdk::server::ContainerEndpoint>,
    SocketRegistrationGuard,
)> {
    let serial = serial_socket::file::FileSerialConfig::new(
        crate::host_platform::stderr_file()
            .context("duplicating stderr for guest serial output")?,
        "stderr".to_owned(),
    )
    .into_resource();
    let chipset_builder = VmManifestBuilder::new(
        BaseChipsetType::UnenlightenedLinuxDirect,
        MachineArch::X86_64,
    )
    .with_serial([Some(serial), None, None, None]);
    let layout = chipset_builder.layout_config();
    let mut chipset = chipset_builder
        .build()
        .context("building OpenVMM chipset")?;
    // OpenVMM's Linux-direct chipset does not expose a PCI bus by default.
    // Virtio PCI devices need both the bus and its legacy INTx route.
    chipset.chipset.with_generic_pci_bus = true;

    let mut virtio_devices: Vec<(
        openvmm_defs::config::VirtioBus,
        vm_resource::Resource<VirtioDeviceHandle>,
    )> = Vec::new();
    virtio_devices.push((
        openvmm_defs::config::VirtioBus::Mmio,
        manager_vsock.into_resource(),
    ));
    for (index, path) in deployment.task_packages.iter().enumerate() {
        let disk = open_file_disk(path, true)
            .with_context(|| format!("opening rootfs disk {}", path.display()))?;
        virtio_devices.push((
            openvmm_defs::config::VirtioBus::Mmio,
            virtio_resources::blk::VirtioBlkHandle {
                disk,
                read_only: true,
                serial: Some(format!("rootfs-{index}")),
            }
            .into_resource(),
        ));
    }

    for (index, mount) in deployment.mounts.iter().enumerate() {
        if matches!(
            &mount.mount,
            ya_client_model::activity::exe_script_command::VolumeMount::Storage { .. }
        ) {
            let path = work_dir.join(&mount.name);
            let disk = open_file_disk(&path, false)
                .with_context(|| format!("opening volume disk {}", path.display()))?;
            virtio_devices.push((
                openvmm_defs::config::VirtioBus::Mmio,
                virtio_resources::blk::VirtioBlkHandle {
                    disk,
                    read_only: false,
                    serial: Some(format!("vol-{index}")),
                }
                .into_resource(),
            ));
        }
    }

    for (index, volume) in deployment.volumes.iter().enumerate() {
        virtio_devices.push((
            openvmm_defs::config::VirtioBus::Mmio,
            crate::shared_dir::SharedDirHandle {
                tag: format!("mnt{index}"),
                root: crate::shared_dir::open_root(work_dir, &volume.name)
                    .with_context(|| format!("opening shared volume {}", volume.name))?,
            }
            .into_resource(),
        ));
    }

    let mut vpn_endpoint = None;
    let mut inet_endpoint = None;
    let mut socket_registrations = SocketRegistrationGuard::default();
    for (iface, remote, target) in [
        (NetworkInterface::Vpn, vpn_remote, &mut vpn_endpoint),
        (NetworkInterface::Inet, inet_remote, &mut inet_endpoint),
    ] {
        let Some(remote) = remote else { continue };
        let (endpoint, exposed) = socket_resource(remote, &mut socket_registrations)?;
        virtio_devices.push((
            openvmm_defs::config::VirtioBus::Mmio,
            NetDeviceHandle {
                mac_address: MacAddress::new([0x90, 0x13, 0, 0, 0, iface as u8 + 1]),
                mtu: crate::network_mtu::device_mtu(iface),
                endpoint,
            }
            .into_resource(),
        ));
        *target = Some(exposed);
    }

    let nvidia_path = runtime_dir.join("nvidia-files.squashfs");
    if nvidia_path.exists() {
        let disk = open_file_disk(&nvidia_path, true).context("opening NVIDIA driver image")?;
        virtio_devices.push((
            openvmm_defs::config::VirtioBus::Pci,
            virtio_resources::blk::VirtioBlkHandle {
                disk,
                read_only: true,
                serial: Some("nvidia-files".to_owned()),
            }
            .into_resource(),
        ));
    }

    virtio_devices.push((
        openvmm_defs::config::VirtioBus::Pci,
        virtio_resources::rng::VirtioRngHandle.into_resource(),
    ));
    let mut cmdline = format!("console=ttyS0 panic=1 hostname={}", deployment.hostname);
    for (index, mount) in deployment.mounts.iter().enumerate() {
        match &mount.mount {
            VolumeMount::Host {} => log::warn!("unexpected host mount in guest volume list"),
            VolumeMount::Storage { errors, .. } => {
                cmdline.push_str(&format!(" vol-{index}-path={}", mount.guest_path));
                cmdline.push_str(&format!(
                    " vol-{index}-errors={}",
                    errors.as_deref().unwrap_or("continue")
                ));
            }
            VolumeMount::Ram { size } => {
                cmdline.push_str(&format!(" vol-{index}-path={}", mount.guest_path));
                cmdline.push_str(&format!(" vol-{index}-size={}", size.as_u64()));
            }
        }
    }
    let mem_size = u64::try_from(deployment.mem_mib)
        .context("guest memory size does not fit u64")?
        .checked_mul(1024 * 1024)
        .context("guest memory size overflow")?;
    let proc_count = u32::try_from(deployment.cpu_cores)
        .context("guest processor count does not fit OpenVMM limits")?;

    let (pcie_root_complexes, pcie_devices) = vfio_config(pci_device_ids)?;
    let config = Config {
        load_mode: LoadMode::Linux {
            kernel: File::open(runtime_dir.join("vmlinuz-virt")).context("opening guest kernel")?,
            initrd: Some(
                File::open(runtime_dir.join("initramfs.cpio.gz"))
                    .context("opening guest initramfs")?,
            ),
            cmdline,
            enable_serial: true,
            isolation: LinuxIsolationConfig::None,
            boot_mode: LinuxDirectBootMode::Acpi,
            smbios: Box::default(),
        },
        floppy_disks: Vec::new(),
        ide_disks: Vec::new(),
        pcie_root_complexes,
        pcie_ecam_below_4gb: false,
        pcie_devices,
        pcie_switches: Vec::new(),
        pcie_generic_initiators: Vec::new(),
        vpci_devices: Vec::new(),
        #[cfg(windows)]
        kernel_vmnics: Vec::new(),
        #[cfg(windows)]
        vpci_resources: Vec::new(),
        numa: NumaTopology {
            nodes: vec![NumaNode {
                mem: Some(MemoryConfig {
                    mem_size,
                    prefetch_memory: false,
                    private_memory: false,
                    transparent_hugepages: true,
                    hugepages: false,
                    hugepage_size: None,
                    host_numa_node: None,
                }),
                vps: VpAssignment::FromTopology,
            }],
            distances: Vec::new(),
        },
        processor_topology: ProcessorTopologyConfig {
            proc_count,
            vps_per_socket: None,
            enable_smt: Some(false),
            arch: Some(ArchTopologyConfig::X86(X86TopologyConfig::default())),
        },
        hypervisor: Default::default(),
        chipset: chipset.chipset,
        vmbus: None,
        vtl2_vmbus: None,
        input: mesh::Receiver::new(),
        framebuffer: None,
        vga_firmware: None,
        vtl2_gfx: false,
        virtio_devices,
        vmgs: Some(vmgs_resources::VmgsResource::Ephemeral),
        firmware_event_send: None,
        debugger_rpc: None,
        vmbus_devices: Vec::new(),
        chipset_devices: chipset.chipset_devices,
        pci_chipset_devices: chipset.pci_chipset_devices,
        isa_dma_controller: chipset.isa_dma_controller,
        chipset_capabilities: chipset.capabilities,
        layout,
        rtc_delta_milliseconds: 0,
    };
    Ok((config, vpn_endpoint, inet_endpoint, socket_registrations))
}

#[cfg(target_os = "linux")]
fn vfio_config(
    pci_device_ids: &[String],
) -> anyhow::Result<(Vec<PcieRootComplexConfig>, Vec<PcieDeviceConfig>)> {
    if pci_device_ids.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut ports = Vec::with_capacity(pci_device_ids.len());
    let mut devices = Vec::with_capacity(pci_device_ids.len());
    for (index, pci_id) in pci_device_ids.iter().enumerate() {
        let sysfs_path = Path::new("/sys/bus/pci/devices").join(pci_id);
        let group_link = std::fs::read_link(sysfs_path.join("iommu_group"))
            .with_context(|| format!("reading IOMMU group for PCI device {pci_id}"))?;
        let group_id = group_link
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid VFIO IOMMU group link")?;
        let group = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/vfio/{group_id}"))
            .with_context(|| format!("opening VFIO group {group_id} for {pci_id}"))?;
        let port_name = format!("rp{index}");
        ports.push(PciePortConfig {
            name: port_name.clone(),
            devfn: None,
            hotplug: false,
            acs_capabilities_supported: None,
            cxl: false,
            pasid: false,
        });
        devices.push(PcieDeviceConfig {
            port_name,
            resource: vfio_assigned_device_resources::VfioDeviceHandle {
                pci_id: pci_id.clone(),
                group,
                bar_addresses: [vfio_assigned_device_resources::BarAddressConfig::GuestAssigned; 6],
            }
            .into_resource(),
        });
    }

    Ok((
        vec![PcieRootComplexConfig {
            index: 0,
            name: "rc0".to_owned(),
            segment: 0,
            start_bus: 0,
            end_bus: 255,
            low_mmio: PcieMmioRangeConfig::Dynamic {
                size: 64 * 1024 * 1024,
            },
            high_mmio: PcieMmioRangeConfig::Dynamic {
                size: 1024 * 1024 * 1024,
            },
            ports,
            cxl: None,
            iommu: None,
            vnode: None,
            preserve_bars: false,
        }],
        devices,
    ))
}

#[cfg(not(target_os = "linux"))]
fn vfio_config(
    pci_device_ids: &[String],
) -> anyhow::Result<(Vec<PcieRootComplexConfig>, Vec<PcieDeviceConfig>)> {
    anyhow::ensure!(
        pci_device_ids.is_empty(),
        "GPU/PCI passthrough is only supported on Linux"
    );
    Ok((Vec::new(), Vec::new()))
}

fn open_file_disk(
    path: &Path,
    read_only: bool,
) -> anyhow::Result<vm_resource::Resource<DiskHandleKind>> {
    let file = if read_only {
        File::open(path)?
    } else {
        OpenOptions::new().read(true).write(true).open(path)?
    };
    Ok(disk_backend_resources::FileDiskHandle(file).into_resource())
}

/// A virtio-net device with a per-device MTU. Upstream `VirtioNetHandle` has
/// no MTU field; the vendored `virtio_net` crate provides the builder option.
#[derive(MeshPayload)]
pub struct NetDeviceHandle {
    mac_address: MacAddress,
    mtu: u16,
    endpoint: vm_resource::Resource<NetEndpointHandleKind>,
}

impl ResourceId<VirtioDeviceHandle> for NetDeviceHandle {
    const ID: &'static str = "ya-runtime-virtio-net";
}

pub struct NetDeviceResolver;
declare_static_async_resolver!(NetDeviceResolver, (VirtioDeviceHandle, NetDeviceHandle));
vm_resource::register_static_resolvers! { NetDeviceResolver }

#[async_trait::async_trait]
impl AsyncResolveResource<VirtioDeviceHandle, NetDeviceHandle> for NetDeviceResolver {
    type Output = ResolvedVirtioDevice;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        resource: NetDeviceHandle,
        input: VirtioResolveInput<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let endpoint = resolver
            .resolve(
                resource.endpoint,
                ResolveEndpointParams {
                    mac_address: resource.mac_address,
                },
            )
            .await?;
        let device = virtio_net::Device::builder().mtu(resource.mtu).build(
            input.driver_source,
            endpoint.0,
            resource.mac_address,
        )?;
        Ok(device.into())
    }
}

#[derive(Clone, Debug, PartialEq, MeshPayload)]
pub struct SocketHandle {
    id: String,
}

impl ResourceId<NetEndpointHandleKind> for SocketHandle {
    const ID: &'static str = "ya-runtime-socket";
}

pub struct RuntimeSocketResolver;
declare_static_resolver!(RuntimeSocketResolver, (NetEndpointHandleKind, SocketHandle));
vm_resource::register_static_resolvers! { RuntimeSocketResolver }

impl ResolveResource<NetEndpointHandleKind, SocketHandle> for RuntimeSocketResolver {
    type Output = ResolvedEndpoint;
    type Error = anyhow::Error;

    fn resolve(
        &self,
        resource: SocketHandle,
        _input: ResolveEndpointParams,
    ) -> Result<Self::Output, Self::Error> {
        Ok(take_registered_endpoint(&resource.id)?.into())
    }
}

fn socket_resource(
    remote: &ya_runtime_sdk::server::ContainerEndpoint,
    registrations: &mut SocketRegistrationGuard,
) -> anyhow::Result<(
    vm_resource::Resource<NetEndpointHandleKind>,
    ya_runtime_sdk::server::ContainerEndpoint,
)> {
    use ya_runtime_sdk::server::ContainerEndpoint;
    match remote {
        ContainerEndpoint::UdpDatagram(remote) => {
            let remote = *remote;
            let endpoint =
                SocketEndpoint::new(SocketMode::Udp, loopback_for(remote), Some(remote))?;
            let (id, local) = registrations.register(endpoint);
            Ok((
                SocketHandle { id }.into_resource(),
                ContainerEndpoint::UdpDatagram(local),
            ))
        }
        ContainerEndpoint::TcpStream(remote) => {
            let remote = *remote;
            let endpoint =
                SocketEndpoint::new(SocketMode::TcpConnect, loopback_for(remote), Some(remote))?;
            let (id, _) = registrations.register(endpoint);
            Ok((
                SocketHandle { id }.into_resource(),
                ContainerEndpoint::TcpStream(remote),
            ))
        }
        ContainerEndpoint::TcpListener(_) => {
            let endpoint = SocketEndpoint::new(
                SocketMode::TcpListen,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                None,
            )?;
            let (id, local) = registrations.register(endpoint);
            Ok((
                SocketHandle { id }.into_resource(),
                ContainerEndpoint::TcpStream(local),
            ))
        }
        _ => anyhow::bail!("unsupported network endpoint type: {remote:?}"),
    }
}

fn loopback_for(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::V6(_) => {
            SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        }
    }
}
