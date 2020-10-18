use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::cell::RefCell;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

const PROGRESS_SIMPLE: &'static str =
    "{spinner:.white} {prefix:.bold.dim} {msg} [{elapsed_precise}] [{bar:40.grey}] {percent}%";
const PROGRESS_ETA: &'static str =
    "{spinner:.white} {prefix:.bold.dim} {msg} [{elapsed_precise}] [{bar:40.grey}] {bytes}/{total_bytes} ({eta})";
const PROGRESS_OK: &'static str =
    "{spinner:.green} {prefix:.bold.dim} {msg} [{elapsed_precise}] [{bar:40.green}]";
const PROGRESS_ERR: &'static str = "{spinner:.red} {prefix:.bold.dim} {msg:.red}";

const SPINNER: &'static str = "{spinner:.white} {prefix:.bold.dim} {msg}";
const SPINNER_OK: &'static str = "{spinner:.green} {prefix:.bold.dim} {msg}";
const SPINNER_ERR: &'static str = "{spinner:.red} {prefix:.bold.dim} {msg}";

const REFRESH_MS: u64 = 500;

static SPINNER_TICKS: &'static [&'static str] = &["∙∙∙", "●∙∙", "∙●∙", "∙∙●", "∙∙∙"];
static OK_TICK: &'static [&'static str] = &[" ✓ "];
static ERR_TICK: &'static [&'static str] = &[" ✗ "];

static STEP_COUNTER: AtomicUsize = AtomicUsize::new(1);

lazy_static::lazy_static! {
    static ref PROGRESS_SIMPLE_STYLE: ProgressStyle = ProgressStyle::default_bar()
        .tick_strings(SPINNER_TICKS)
        .template(PROGRESS_SIMPLE);

    static ref PROGRESS_ETA_STYLE: ProgressStyle = ProgressStyle::default_bar()
        .tick_strings(SPINNER_TICKS)
        .template(PROGRESS_ETA);

    static ref PROGRESS_OK_STYLE: ProgressStyle = ProgressStyle::default_bar()
        .tick_strings(OK_TICK)
        .template(PROGRESS_OK);

    static ref PROGRESS_ERR_STYLE: ProgressStyle = ProgressStyle::default_bar()
        .tick_strings(ERR_TICK)
        .template(PROGRESS_ERR);

    static ref SPINNER_STYLE: ProgressStyle = ProgressStyle::default_spinner()
            .tick_strings(SPINNER_TICKS)
            .template(SPINNER.clone());

    static ref SPINNER_OK_STYLE: ProgressStyle = ProgressStyle::default_spinner()
            .tick_strings(OK_TICK)
            .template(SPINNER_OK.clone());

    static ref SPINNER_ERR_STYLE: ProgressStyle = ProgressStyle::default_spinner()
            .tick_strings(ERR_TICK)
            .template(SPINNER_ERR.clone());

    static ref TOTAL_STEPS: Mutex<usize> = Mutex::new(0);
    static ref PERCENT_REGEX: Regex = Regex::new(r"\d+%").unwrap();
}

pub(crate) fn set_total_steps(count: usize) {
    *(TOTAL_STEPS.lock().unwrap()) = count;
}

pub(crate) fn from_progress_output<S: AsRef<str>>(src: S) -> Option<usize> {
    (*PERCENT_REGEX)
        .find(src.as_ref())
        .map(|m| src.as_ref()[m.start()..m.end()].trim_end_matches('%'))
        .map(|s| s.parse().ok())
        .flatten()
}

pub(crate) struct Progress {
    inner: ProgressBar,
}

impl Progress {
    pub fn new<S: AsRef<str>>(msg: S, total: u64) -> Self {
        let prefix = format!(
            "[{}/{}]",
            STEP_COUNTER.fetch_add(1, Relaxed),
            TOTAL_STEPS.lock().unwrap()
        );

        let inner = ProgressBar::new(total).with_style(PROGRESS_SIMPLE_STYLE.clone());
        inner.set_prefix(prefix.as_str());
        inner.set_message(msg.as_ref());
        inner.enable_steady_tick(REFRESH_MS);

        Progress { inner }
    }

    pub fn with_eta<S: AsRef<str>>(msg: S, total: u64) -> Self {
        let progress = Self::new(msg, total);
        progress.inner.set_style(PROGRESS_ETA_STYLE.clone());
        progress
    }

    pub fn position(&self) -> u64 {
        self.inner.position()
    }

    pub fn inc(&self, delta: u64) {
        self.inner.inc(delta);
    }

    pub fn set_total(&self, total: u64) {
        self.inner.set_length(total);
    }

    pub fn set_message<S: AsRef<str>>(&self, msg: S) {
        self.inner.set_message(msg.as_ref());
    }

    pub fn success(&self) {
        self.inner.set_style(PROGRESS_OK_STYLE.clone());
        self.inner.finish();
    }

    pub fn failure(&self) {
        self.inner.set_style(PROGRESS_ERR_STYLE.clone());
        self.inner.finish();
    }
}

pub(crate) struct Spinner {
    inner: ProgressBar,
    message: RefCell<String>,
}

impl Spinner {
    pub fn new<S: AsRef<str>>(msg: S) -> Self {
        let prefix = format!(
            "[{}/{}]",
            STEP_COUNTER.fetch_add(1, Relaxed),
            TOTAL_STEPS.lock().unwrap()
        );

        let inner = ProgressBar::new(!0).with_style(SPINNER_STYLE.clone());
        inner.set_prefix(prefix.as_str());
        inner.set_message(msg.as_ref());

        Spinner {
            inner,
            message: RefCell::new(msg.as_ref().to_string()),
        }
    }

    pub fn ticking(self) -> Self {
        self.inner.enable_steady_tick(REFRESH_MS);
        self
    }

    pub fn message(&self) -> String {
        self.message.borrow().clone()
    }

    pub fn set_message<S: AsRef<str>>(&self, msg: S) {
        self.message.replace(msg.as_ref().to_string());
        self.inner.set_message(msg.as_ref());
    }

    pub fn success(&self) {
        self.inner.set_style(SPINNER_OK_STYLE.clone());
        self.inner.finish();
    }

    pub fn failure(&self) {
        self.inner.set_style(SPINNER_ERR_STYLE.clone());
        self.inner.finish();
    }
}

pub(crate) trait ProgressResult<T, E> {
    fn progress_err(self, progress: &Progress) -> Result<T, E>;
    fn progress_result(self, progress: &Progress) -> Result<T, E>;
}

impl<T, E: Debug> ProgressResult<T, E> for Result<T, E> {
    fn progress_err(self, progress: &Progress) -> Result<T, E> {
        if let Err(e) = &self {
            progress.set_message(format!("{:?}", e));
            progress.failure();
        }
        self
    }

    fn progress_result(self, progress: &Progress) -> Result<T, E> {
        match &self {
            Ok(_) => {
                progress.success();
                self
            }
            Err(_) => self.progress_err(progress),
        }
    }
}

pub(crate) trait SpinnerResult<T, E> {
    fn spinner_err(self, spinner: &Spinner) -> Result<T, E>;
    fn spinner_result(self, spinner: &Spinner) -> Result<T, E>;
}

impl<T, E: Debug> SpinnerResult<T, E> for Result<T, E> {
    fn spinner_err(self, spinner: &Spinner) -> Result<T, E> {
        if let Err(e) = &self {
            let message = format!("{}: {:?}", spinner.message(), e);
            spinner.set_message(message);
            spinner.failure();
        }
        self
    }

    fn spinner_result(self, spinner: &Spinner) -> Result<T, E> {
        match &self {
            Ok(_) => {
                spinner.success();
                self
            }
            Err(_) => self.spinner_err(spinner),
        }
    }
}
