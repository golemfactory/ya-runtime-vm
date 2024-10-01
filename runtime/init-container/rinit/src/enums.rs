pub enum EpollFdType {
    Cmds,
    Sig,
    Out,
    In,
}

pub enum MessageRunProcessType {
    End,
    Bin,
    Arg,
    Env,
    Uid,
    Gid,
    Rfd,
    Cwd,
    Ent,
}

pub enum MessageKillProcessType {
    Pid,
}

pub enum MessageMountVolumeType {
    Tag,
    Path,
}

pub enum MessageUploadFileType {
    Path,
    Perm,
    User,
    Group,
    Data,
}

#[derive(Default, Debug)]
pub enum RedirectFdType {
    #[default]
    Invalid = -1,
    File = 0,
    PipeBlocking,
    PipeCyclic,
}

#[derive(Default, Debug)]
pub enum MessageType {
    #[default]
    None = 0,
    Quit = 1,
    RunProcess,
    KillProcess,
    MountVolume,
    UploadFile,
    QueryOutput,
    PutInput,
    SyncFs,
    NetCtl,
    NetHost,
}

pub enum Response {
    Ok = 0,
    Error = 3,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Quit,
            2 => Self::RunProcess,
            3 => Self::KillProcess,
            4 => Self::MountVolume,
            5 => Self::UploadFile,
            6 => Self::QueryOutput,
            7 => Self::PutInput,
            8 => Self::SyncFs,
            9 => Self::NetCtl,
            10 => Self::NetHost,
            _ => Self::None,
        }
    }
}

impl MessageRunProcessType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::End,
            1 => Self::Bin,
            2 => Self::Arg,
            3 => Self::Env,
            4 => Self::Uid,
            5 => Self::Gid,
            6 => Self::Rfd,
            7 => Self::Cwd,
            8 => Self::Ent,
            _ => Self::End,
        }
    }
}

impl RedirectFdType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::File,
            1 => Self::PipeBlocking,
            2 => Self::PipeCyclic,
            _ => Self::Invalid,
        }
    }
}

impl From<EpollFdType> for u64 {
    fn from(fd_type: EpollFdType) -> Self {
        match fd_type {
            EpollFdType::Cmds => 1,
            EpollFdType::Sig => 2,
            EpollFdType::Out => 3,
            EpollFdType::In => 4,
        }
    }
}
