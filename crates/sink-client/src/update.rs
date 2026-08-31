//! Stable, verified self-updates for the Sink client binary.

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use directories::ProjectDirs;
use self_update::{Release, ReleaseAsset, VersionStatus, backends::github};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Set this to `1` to skip the best-effort automatic update check.
pub const UPDATE_CHECK_DISABLE_ENV: &str = "SINK_NO_UPDATE_CHECK";

const REPOSITORY_OWNER: &str = "ptrstovka";
const REPOSITORY_NAME: &str = "sink";
const GITHUB_API_BASE_URL: &str = "https://api.github.com";
const BINARY_NAME: &str = "sink";
const CHECKSUM_ASSET_NAME: &str = "SHA256SUMS";
const CACHE_FILE_NAME: &str = "update-check-v1.json";
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const METADATA_TIMEOUT: Duration = Duration::from_secs(8);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A complete stable release that is newer than this Sink client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableUpdate {
    current_version: String,
    latest_version: String,
}

impl AvailableUpdate {
    /// The running Sink client's version.
    #[must_use]
    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    /// The newest complete stable release's version.
    #[must_use]
    pub fn latest_version(&self) -> &str {
        &self.latest_version
    }
}

/// Outcome of an explicit self-update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateResult {
    /// The running binary is already at or ahead of the latest stable release.
    UpToDate { version: String },
    /// The running binary was replaced by the verified release binary.
    Updated {
        previous_version: String,
        current_version: String,
    },
}

/// Errors returned by update checks and explicit installs.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("self-update is unsupported on {os}/{arch}")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("the platform cache directory is unavailable")]
    CacheDirectoryUnavailable,

    #[error("could not determine the current executable path")]
    CurrentExecutable(#[source] io::Error),

    #[error("the system clock is earlier than the Unix epoch")]
    SystemClock(#[source] SystemTimeError),

    #[error("could not read update cache {path}")]
    CacheRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("could not decode update cache {path}")]
    CacheDecode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("could not create update cache directory {path}")]
    CacheDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("could not create a temporary update cache file in {path}")]
    CacheCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("could not encode update cache {path}")]
    CacheEncode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("could not flush update cache {path}")]
    CacheFlush {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("could not atomically replace update cache {path}")]
    CachePersist {
        path: PathBuf,
        #[source]
        source: tempfile::PersistError,
    },

    #[error("invalid {kind} version `{version}`")]
    InvalidVersion {
        kind: &'static str,
        version: String,
        #[source]
        source: semver::Error,
    },

    #[error("could not query the latest stable Sink release")]
    ReleaseLookup(#[source] self_update::Error),

    #[error("the latest stable release response contained no release")]
    EmptyLatestRelease,

    #[error("release v{version} is not installable: {reason}")]
    ReleaseNotReady { version: String, reason: String },

    #[error("could not install Sink v{version}: {source}")]
    Install {
        version: String,
        #[source]
        source: self_update::Error,
    },

    #[error(
        "the updater reported version `{actual}` after installing expected version `{expected}`"
    )]
    InstallResultMismatch { expected: String, actual: String },
}

/// Returns `true` exactly when automatic update checks have been opted out with
/// `SINK_NO_UPDATE_CHECK=1`.
#[must_use]
pub fn automatic_check_disabled() -> bool {
    automatic_check_disabled_value(env::var_os(UPDATE_CHECK_DISABLE_ENV).as_deref())
}

/// Check the stable release endpoint when the 24-hour cache is stale.
///
/// A cached ready release remains visible on every call in the cache window. A cached
/// up-to-date or incomplete result suppresses another request for the same window.
pub async fn check_for_update_if_due() -> Result<Option<AvailableUpdate>, UpdateError> {
    if automatic_check_disabled() {
        return Ok(None);
    }

    let settings = UpdateSettings::production()?;
    check_for_update_if_due_with(&settings).await
}

/// Install the newest complete stable release over this `sink` executable.
///
/// This always performs a fresh lookup and is intentionally unaffected by the automatic-check
/// cache and opt-out environment variable.
pub async fn install_latest() -> Result<UpdateResult, UpdateError> {
    let settings = UpdateSettings::production()?;
    install_latest_with(&settings).await
}

#[derive(Clone, Debug)]
struct UpdateSettings {
    api_base_url: String,
    cache_path: PathBuf,
    current_version: String,
    install_path: PathBuf,
    os: String,
    arch: String,
    now_unix_seconds: u64,
}

impl UpdateSettings {
    fn production() -> Result<Self, UpdateError> {
        let project_dirs =
            ProjectDirs::from("", "", "sink").ok_or(UpdateError::CacheDirectoryUnavailable)?;
        let install_path = env::current_exe().map_err(UpdateError::CurrentExecutable)?;
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(UpdateError::SystemClock)?
            .as_secs();

        Ok(Self {
            api_base_url: GITHUB_API_BASE_URL.to_owned(),
            cache_path: project_dirs.cache_dir().join(CACHE_FILE_NAME),
            current_version: env!("CARGO_PKG_VERSION").to_owned(),
            install_path,
            os: env::consts::OS.to_owned(),
            arch: env::consts::ARCH.to_owned(),
            now_unix_seconds,
        })
    }

    fn platform_suffix(&self) -> Result<&'static str, UpdateError> {
        platform_suffix(&self.os, &self.arch)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CacheRecord {
    checked_at_unix_seconds: u64,
    current_version: String,
    platform: String,
    ready_version: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum ReleaseReadiness {
    UpToDate,
    NotReady { version: String, reason: String },
    Ready { version: String, asset_name: String },
}

async fn check_for_update_if_due_with(
    settings: &UpdateSettings,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    if let Some(record) = read_fresh_cache(settings)? {
        return available_from_cache(settings, record.ready_version.as_deref());
    }

    let readiness = match fetch_latest_readiness(settings).await {
        Ok(readiness) => readiness,
        Err(error) => {
            if let Err(cache_error) = write_cache(settings, None) {
                tracing::debug!(
                    %cache_error,
                    lookup_error = %error,
                    "could not cache failed automatic update lookup"
                );
            }
            return Err(error);
        }
    };
    let ready_version = match &readiness {
        ReleaseReadiness::Ready { version, .. } => Some(version.clone()),
        ReleaseReadiness::UpToDate | ReleaseReadiness::NotReady { .. } => None,
    };
    write_cache(settings, ready_version.as_deref())?;

    Ok(match readiness {
        ReleaseReadiness::Ready { version, .. } => Some(AvailableUpdate {
            current_version: settings.current_version.clone(),
            latest_version: version,
        }),
        ReleaseReadiness::UpToDate | ReleaseReadiness::NotReady { .. } => None,
    })
}

async fn install_latest_with(settings: &UpdateSettings) -> Result<UpdateResult, UpdateError> {
    let readiness = fetch_latest_readiness(settings).await?;
    let (latest_version, asset_name) = match readiness {
        ReleaseReadiness::UpToDate => {
            return Ok(UpdateResult::UpToDate {
                version: settings.current_version.clone(),
            });
        }
        ReleaseReadiness::NotReady { version, reason } => {
            return Err(UpdateError::ReleaseNotReady { version, reason });
        }
        ReleaseReadiness::Ready {
            version,
            asset_name,
        } => (version, asset_name),
    };

    let expected_asset_name = asset_name.clone();
    let verified_version = latest_version.clone();
    let mut builder = base_builder(settings, INSTALL_TIMEOUT)?;
    builder
        .release_tag(format!("v{latest_version}"))
        .asset_matcher(move |assets| exact_asset(assets, &expected_asset_name))
        .checksum_from_asset(CHECKSUM_ASSET_NAME)
        .verify_release_digest(true)
        .check_install_path_writable(true)
        .no_confirm(true)
        .show_output(false)
        .show_download_progress(true)
        .verify_binary(move |path| verify_staged_binary(path, &verified_version));
    let updater = builder
        .build_async()
        .map_err(|source| UpdateError::Install {
            version: latest_version.clone(),
            source,
        })?;
    let status = updater
        .update_async()
        .await
        .map_err(|source| UpdateError::Install {
            version: latest_version.clone(),
            source,
        })?;

    validate_install_status(&status, &settings.current_version, &latest_version)
}

async fn fetch_latest_readiness(
    settings: &UpdateSettings,
) -> Result<ReleaseReadiness, UpdateError> {
    let updater = base_builder(settings, METADATA_TIMEOUT)?
        .build_async()
        .map_err(UpdateError::ReleaseLookup)?;
    let releases = updater
        .get_latest_release_async()
        .await
        .map_err(UpdateError::ReleaseLookup)?;
    let release = releases.latest().ok_or(UpdateError::EmptyLatestRelease)?;

    assess_release(
        release,
        &settings.current_version,
        settings.platform_suffix()?,
    )
}

fn base_builder(
    settings: &UpdateSettings,
    timeout: Duration,
) -> Result<github::UpdateBuilder, UpdateError> {
    let platform = settings.platform_suffix()?;
    let mut builder = github::Update::configure();
    builder
        .repo_owner(REPOSITORY_OWNER)
        .repo_name(REPOSITORY_NAME)
        .api_base_url(&settings.api_base_url)
        .current_version(&settings.current_version)
        .target(platform)
        .bin_name(BINARY_NAME)
        .bin_path_in_archive(BINARY_NAME)
        .bin_install_path(&settings.install_path)
        .timeout(timeout);
    Ok(builder)
}

fn assess_release(
    release: &Release,
    current_version: &str,
    platform: &str,
) -> Result<ReleaseReadiness, UpdateError> {
    let current = parse_version("current", current_version)?;
    let latest = parse_version("latest release", release.version())?;

    if latest <= current {
        return Ok(ReleaseReadiness::UpToDate);
    }

    if !latest.pre.is_empty() {
        return Ok(ReleaseReadiness::NotReady {
            version: latest.to_string(),
            reason: "the version is a prerelease".to_owned(),
        });
    }

    let asset_name = archive_asset_name(&latest, platform);
    let has_archive = release
        .assets()
        .iter()
        .any(|asset| asset.name() == asset_name);
    let has_checksums = release
        .assets()
        .iter()
        .any(|asset| asset.name() == CHECKSUM_ASSET_NAME);

    let mut missing = Vec::new();
    if !has_archive {
        missing.push(asset_name.as_str());
    }
    if !has_checksums {
        missing.push(CHECKSUM_ASSET_NAME);
    }
    if !missing.is_empty() {
        return Ok(ReleaseReadiness::NotReady {
            version: latest.to_string(),
            reason: format!("missing required asset(s): {}", missing.join(", ")),
        });
    }

    Ok(ReleaseReadiness::Ready {
        version: latest.to_string(),
        asset_name,
    })
}

fn parse_version(kind: &'static str, version: &str) -> Result<Version, UpdateError> {
    Version::parse(version).map_err(|source| UpdateError::InvalidVersion {
        kind,
        version: version.to_owned(),
        source,
    })
}

fn platform_suffix(os: &str, arch: &str) -> Result<&'static str, UpdateError> {
    match (os, arch) {
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        _ => Err(UpdateError::UnsupportedPlatform {
            os: os.to_owned(),
            arch: arch.to_owned(),
        }),
    }
}

fn archive_asset_name(version: &Version, platform: &str) -> String {
    format!("sink-v{version}-{platform}.tar.gz")
}

fn exact_asset(assets: &[ReleaseAsset], expected_name: &str) -> Option<ReleaseAsset> {
    assets
        .iter()
        .find(|asset| asset.name() == expected_name)
        .cloned()
}

fn automatic_check_disabled_value(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

fn read_fresh_cache(settings: &UpdateSettings) -> Result<Option<CacheRecord>, UpdateError> {
    let bytes = match fs::read(&settings.cache_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(UpdateError::CacheRead {
                path: settings.cache_path.clone(),
                source,
            });
        }
    };
    let record: CacheRecord =
        serde_json::from_slice(&bytes).map_err(|source| UpdateError::CacheDecode {
            path: settings.cache_path.clone(),
            source,
        })?;

    let age = settings
        .now_unix_seconds
        .checked_sub(record.checked_at_unix_seconds);
    Ok(match age {
        Some(seconds)
            if seconds < CACHE_TTL.as_secs()
                && record.current_version == settings.current_version
                && record.platform == settings.platform_suffix()? =>
        {
            Some(record)
        }
        Some(_) | None => None,
    })
}

fn available_from_cache(
    settings: &UpdateSettings,
    ready_version: Option<&str>,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let Some(latest_version) = ready_version else {
        return Ok(None);
    };
    let current = parse_version("current", &settings.current_version)?;
    let latest = parse_version("cached release", latest_version)?;
    if latest <= current || !latest.pre.is_empty() {
        return Ok(None);
    }

    Ok(Some(AvailableUpdate {
        current_version: settings.current_version.clone(),
        latest_version: latest.to_string(),
    }))
}

fn write_cache(settings: &UpdateSettings, ready_version: Option<&str>) -> Result<(), UpdateError> {
    let parent = settings
        .cache_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| UpdateError::CacheDirectory {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| UpdateError::CacheCreate {
            path: parent.to_path_buf(),
            source,
        })?;
    let record = CacheRecord {
        checked_at_unix_seconds: settings.now_unix_seconds,
        current_version: settings.current_version.clone(),
        platform: settings.platform_suffix()?.to_owned(),
        ready_version: ready_version.map(str::to_owned),
    };
    serde_json::to_writer(temporary.as_file_mut(), &record).map_err(|source| {
        UpdateError::CacheEncode {
            path: settings.cache_path.clone(),
            source,
        }
    })?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|source| UpdateError::CacheFlush {
            path: settings.cache_path.clone(),
            source,
        })?;
    temporary
        .persist(&settings.cache_path)
        .map_err(|source| UpdateError::CachePersist {
            path: settings.cache_path.clone(),
            source,
        })?;
    Ok(())
}

fn verify_staged_binary(path: &Path, expected_version: &str) -> self_update::Result<()> {
    let output = Command::new(path)
        .arg("version")
        .output()
        .map_err(|error| {
            self_update::Error::verification_rejected(format!(
                "could not execute staged binary {}: {error}",
                path.display()
            ))
        })?;
    if !output.status.success() {
        return Err(self_update::Error::verification_rejected(format!(
            "staged binary {} exited with {status}",
            path.display(),
            status = output.status
        )));
    }

    let expected_stdout = format!("sink {expected_version}\n");
    if output.stdout != expected_stdout.as_bytes() {
        return Err(self_update::Error::verification_rejected(format!(
            "staged binary printed {:?}, expected {:?}",
            String::from_utf8_lossy(&output.stdout),
            expected_stdout
        )));
    }
    Ok(())
}

fn validate_install_status(
    status: &VersionStatus,
    previous_version: &str,
    expected_version: &str,
) -> Result<UpdateResult, UpdateError> {
    if !status.is_updated() || status.version() != expected_version {
        return Err(UpdateError::InstallResultMismatch {
            expected: expected_version.to_owned(),
            actual: status.version().to_owned(),
        });
    }
    Ok(UpdateResult::Updated {
        previous_version: previous_version.to_owned(),
        current_version: expected_version.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, io::Cursor, sync::Arc};

    use axum::{
        Router,
        body::Body,
        extract::State,
        http::{StatusCode, Uri},
        response::Response,
        routing::any,
    };
    use flate2::{Compression, write::GzEncoder};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[test]
    fn maps_only_the_four_release_platforms() -> TestResult {
        assert_eq!(platform_suffix("macos", "aarch64")?, "macos-arm64");
        assert_eq!(platform_suffix("macos", "x86_64")?, "macos-x86_64");
        assert_eq!(platform_suffix("linux", "aarch64")?, "linux-arm64");
        assert_eq!(platform_suffix("linux", "x86_64")?, "linux-x86_64");
        assert!(matches!(
            platform_suffix("windows", "x86_64"),
            Err(UpdateError::UnsupportedPlatform { .. })
        ));
        assert!(matches!(
            platform_suffix("linux", "arm"),
            Err(UpdateError::UnsupportedPlatform { .. })
        ));
        Ok(())
    }

    #[test]
    fn release_is_ready_only_with_both_exact_assets() -> TestResult {
        let archive = "sink-v2.0.0-linux-x86_64.tar.gz";
        let complete = test_release("2.0.0", &[archive, CHECKSUM_ASSET_NAME])?;
        assert_eq!(
            assess_release(&complete, "1.0.0", "linux-x86_64")?,
            ReleaseReadiness::Ready {
                version: "2.0.0".to_owned(),
                asset_name: archive.to_owned(),
            }
        );

        let similar = test_release(
            "2.0.0",
            &["prefix-sink-v2.0.0-linux-x86_64.tar.gz", "SHA256SUMS.txt"],
        )?;
        let ReleaseReadiness::NotReady { reason, .. } =
            assess_release(&similar, "1.0.0", "linux-x86_64")?
        else {
            return Err("similar asset names unexpectedly made the release ready".into());
        };
        assert!(reason.contains(archive));
        assert!(reason.contains(CHECKSUM_ASSET_NAME));
        Ok(())
    }

    #[test]
    fn stable_versions_must_be_strictly_newer() -> TestResult {
        for latest in ["1.0.0", "0.9.9"] {
            let release = test_release(latest, &[])?;
            assert_eq!(
                assess_release(&release, "1.0.0", "linux-x86_64")?,
                ReleaseReadiness::UpToDate
            );
        }

        let prerelease = test_release(
            "2.0.0-beta.1",
            &[
                "sink-v2.0.0-beta.1-linux-x86_64.tar.gz",
                CHECKSUM_ASSET_NAME,
            ],
        )?;
        assert!(matches!(
            assess_release(&prerelease, "1.0.0", "linux-x86_64")?,
            ReleaseReadiness::NotReady { .. }
        ));
        Ok(())
    }

    #[test]
    fn opt_out_is_exactly_the_value_one() {
        assert!(automatic_check_disabled_value(Some(OsStr::new("1"))));
        assert!(!automatic_check_disabled_value(None));
        assert!(!automatic_check_disabled_value(Some(OsStr::new("true"))));
        assert!(!automatic_check_disabled_value(Some(OsStr::new("0"))));
        assert!(!automatic_check_disabled_value(Some(OsStr::new(" 1 "))));
    }

    #[tokio::test]
    async fn fresh_ready_cache_repeats_notice_and_stale_cache_refetches() -> TestResult {
        let directory = tempfile::tempdir()?;
        let archive = "sink-v2.0.0-macos-arm64.tar.gz";
        let server = metadata_server("2.0.0", &[archive, CHECKSUM_ASSET_NAME]).await?;
        let mut settings = test_settings(&directory, &server.base_url, 1_000_000);

        let first = check_for_update_if_due_with(&settings)
            .await?
            .ok_or("the first check did not return the ready release")?;
        assert_eq!(first.current_version(), "1.0.0");
        assert_eq!(first.latest_version(), "2.0.0");
        assert_eq!(server.request_count().await, 1);
        assert_eq!(
            server.request_paths().await,
            vec!["/repos/ptrstovka/sink/releases/latest"]
        );

        let repeated = check_for_update_if_due_with(&settings)
            .await?
            .ok_or("the fresh cache did not repeat the ready release")?;
        assert_eq!(repeated.latest_version(), "2.0.0");
        assert_eq!(server.request_count().await, 1);

        settings.now_unix_seconds += CACHE_TTL.as_secs() - 1;
        assert!(check_for_update_if_due_with(&settings).await?.is_some());
        assert_eq!(server.request_count().await, 1);

        settings.now_unix_seconds += 1;
        assert!(check_for_update_if_due_with(&settings).await?.is_some());
        assert_eq!(server.request_count().await, 2);
        Ok(())
    }

    #[tokio::test]
    async fn up_to_date_and_incomplete_states_are_cached() -> TestResult {
        let up_to_date_dir = tempfile::tempdir()?;
        let up_to_date_server = metadata_server("1.0.0", &[]).await?;
        let mut settings = test_settings(&up_to_date_dir, &up_to_date_server.base_url, 10_000);
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(up_to_date_server.request_count().await, 1);

        settings.current_version = "0.9.0".to_owned();
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(up_to_date_server.request_count().await, 2);
        settings.os = "linux".to_owned();
        settings.arch = "x86_64".to_owned();
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(up_to_date_server.request_count().await, 3);

        let incomplete_dir = tempfile::tempdir()?;
        let incomplete_server =
            metadata_server("2.0.0", &["sink-v2.0.0-macos-arm64.tar.gz"]).await?;
        let settings = test_settings(&incomplete_dir, &incomplete_server.base_url, 20_000);
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(incomplete_server.request_count().await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn cache_decode_errors_return_without_network_access() -> TestResult {
        let directory = tempfile::tempdir()?;
        let server = metadata_server(
            "2.0.0",
            &["sink-v2.0.0-macos-arm64.tar.gz", CHECKSUM_ASSET_NAME],
        )
        .await?;
        let settings = test_settings(&directory, &server.base_url, 30_000);
        fs::create_dir_all(
            settings
                .cache_path
                .parent()
                .ok_or("cache path has no parent")?,
        )?;
        fs::write(&settings.cache_path, b"not json")?;

        assert!(matches!(
            check_for_update_if_due_with(&settings).await,
            Err(UpdateError::CacheDecode { .. })
        ));
        assert_eq!(server.request_count().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn automatic_lookup_failure_is_cached_without_retrying_inside_ttl() -> TestResult {
        let directory = tempfile::tempdir()?;
        let server = TestServer::spawn(|_| Ok(HashMap::new())).await?;
        let settings = test_settings(&directory, &server.base_url, 35_000);

        assert!(matches!(
            check_for_update_if_due_with(&settings).await,
            Err(UpdateError::ReleaseLookup(_))
        ));
        assert_eq!(server.request_count().await, 1);
        assert!(settings.cache_path.is_file());

        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(server.request_count().await, 1);
        assert_eq!(
            server.request_paths().await,
            vec!["/repos/ptrstovka/sink/releases/latest"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn automatic_malformed_release_metadata_is_cached_without_retrying_inside_ttl()
    -> TestResult {
        let directory = tempfile::tempdir()?;
        let server = metadata_server("2.0", &[]).await?;
        let settings = test_settings(&directory, &server.base_url, 35_500);

        let first = check_for_update_if_due_with(&settings).await;
        assert!(
            matches!(&first, Err(UpdateError::ReleaseLookup(_))),
            "unexpected result: {first:?}"
        );
        assert_eq!(server.request_count().await, 1);
        assert!(settings.cache_path.is_file());

        assert!(check_for_update_if_due_with(&settings).await?.is_none());
        assert_eq!(server.request_count().await, 1);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lookup_error_precedes_failure_to_persist_failure_cache() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let server = TestServer::spawn(|_| Ok(HashMap::new())).await?;
        let mut settings = test_settings(&directory, &server.base_url, 36_000);
        let cache_parent = directory.path().join("read-only-cache-parent");
        fs::create_dir(&cache_parent)?;
        settings.cache_path = cache_parent.join(CACHE_FILE_NAME);

        let original_permissions = fs::metadata(&cache_parent)?.permissions();
        let mut read_only_permissions = original_permissions.clone();
        read_only_permissions.set_mode(0o555);
        fs::set_permissions(&cache_parent, read_only_permissions)?;
        let result = check_for_update_if_due_with(&settings).await;
        fs::set_permissions(&cache_parent, original_permissions)?;

        assert!(matches!(result, Err(UpdateError::ReleaseLookup(_))));
        assert!(!settings.cache_path.exists());
        assert_eq!(server.request_count().await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_lookup_failures_remain_uncached() -> TestResult {
        let directory = tempfile::tempdir()?;
        let server = TestServer::spawn(|_| Ok(HashMap::new())).await?;
        let settings = test_settings(&directory, &server.base_url, 37_000);

        for _ in 0..2 {
            assert!(matches!(
                install_latest_with(&settings).await,
                Err(UpdateError::ReleaseLookup(_))
            ));
        }
        assert_eq!(server.request_count().await, 2);
        assert!(!settings.cache_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn explicit_install_is_pinned_verified_and_replaces_only_test_path() -> TestResult {
        let directory = tempfile::tempdir()?;
        let script = verified_script("2.0.0");
        let server = install_server("2.0.0", script.as_bytes(), None).await?;
        let settings = test_settings(&directory, &server.base_url, 40_000);
        fs::write(&settings.install_path, b"original test binary")?;

        assert_eq!(
            install_latest_with(&settings).await?,
            UpdateResult::Updated {
                previous_version: "1.0.0".to_owned(),
                current_version: "2.0.0".to_owned(),
            }
        );
        assert_eq!(fs::read(&settings.install_path)?, script.as_bytes());
        assert!(!directory.path().join("sink-server").exists());
        assert_eq!(
            server.request_paths().await,
            vec![
                "/repos/ptrstovka/sink/releases/latest",
                "/repos/ptrstovka/sink/releases/tags/v2.0.0",
                "/download/SHA256SUMS",
                "/download/archive",
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn staged_binary_mismatch_does_not_replace_install_path() -> TestResult {
        let directory = tempfile::tempdir()?;
        let script = verified_script("9.9.9");
        let server = install_server("2.0.0", script.as_bytes(), None).await?;
        let settings = test_settings(&directory, &server.base_url, 50_000);
        let original = b"original test binary";
        fs::write(&settings.install_path, original)?;

        let error = match install_latest_with(&settings).await {
            Ok(_) => return Err("a staged binary with the wrong version was accepted".into()),
            Err(error) => error,
        };
        let UpdateError::Install { source, .. } = error else {
            return Err("staged binary mismatch returned the wrong error variant".into());
        };
        assert!(source.to_string().contains("staged binary printed"));
        assert_eq!(fs::read(&settings.install_path)?, original);
        Ok(())
    }

    #[tokio::test]
    async fn github_digest_mismatch_does_not_replace_install_path() -> TestResult {
        let directory = tempfile::tempdir()?;
        let script = verified_script("2.0.0");
        let wrong_digest = format!("sha256:{}", "0".repeat(64));
        let server = install_server("2.0.0", script.as_bytes(), Some(&wrong_digest)).await?;
        let settings = test_settings(&directory, &server.base_url, 60_000);
        let original = b"original test binary";
        fs::write(&settings.install_path, original)?;

        let error = match install_latest_with(&settings).await {
            Ok(_) => return Err("a mismatched GitHub digest was accepted".into()),
            Err(error) => error,
        };
        let UpdateError::Install { source, .. } = error else {
            return Err("digest mismatch returned the wrong error variant".into());
        };
        assert!(source.to_string().contains("checksum mismatch"));
        assert_eq!(fs::read(&settings.install_path)?, original);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_error_display_includes_actionable_source_and_preserves_chain() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let script = verified_script("2.0.0");
        let server = install_server("2.0.0", script.as_bytes(), None).await?;
        let settings = test_settings(&directory, &server.base_url, 65_000);
        fs::write(&settings.install_path, b"original test binary")?;

        let original_permissions = fs::metadata(&settings.install_path)?.permissions();
        let mut read_only_permissions = original_permissions.clone();
        read_only_permissions.set_mode(0o555);
        fs::set_permissions(&settings.install_path, read_only_permissions)?;
        let result = install_latest_with(&settings).await;
        fs::set_permissions(&settings.install_path, original_permissions)?;

        let error = match result {
            Ok(_) => return Err("an unwritable install path was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            UpdateError::Install {
                source: self_update::Error::InstallPathNotWritable { .. },
                ..
            }
        ));
        let shown = error.to_string();
        assert!(shown.contains("could not install Sink v2.0.0"));
        assert!(shown.contains("InstallPathNotWritableError"));
        assert!(shown.contains(&settings.install_path.display().to_string()));
        assert!(shown.contains("user-writable install path"));
        assert!(error.source().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn explicit_install_reports_up_to_date_without_downloading() -> TestResult {
        let directory = tempfile::tempdir()?;
        let server = metadata_server("1.0.0", &[]).await?;
        let settings = test_settings(&directory, &server.base_url, 70_000);

        assert_eq!(
            install_latest_with(&settings).await?,
            UpdateResult::UpToDate {
                version: "1.0.0".to_owned(),
            }
        );
        assert_eq!(
            server.request_paths().await,
            vec!["/repos/ptrstovka/sink/releases/latest"]
        );
        Ok(())
    }

    fn test_release(version: &str, asset_names: &[&str]) -> self_update::Result<Release> {
        let assets = asset_names
            .iter()
            .map(|name| ReleaseAsset::new(*name, format!("https://example.invalid/{name}")));
        Release::builder().version(version).assets(assets).build()
    }

    fn test_settings(
        directory: &tempfile::TempDir,
        api_base_url: &str,
        now_unix_seconds: u64,
    ) -> UpdateSettings {
        UpdateSettings {
            api_base_url: api_base_url.to_owned(),
            cache_path: directory.path().join("cache").join(CACHE_FILE_NAME),
            current_version: "1.0.0".to_owned(),
            install_path: directory.path().join("installed-sink"),
            os: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            now_unix_seconds,
        }
    }

    fn verified_script(version: &str) -> String {
        format!(
            "#!/bin/sh\nif [ \"$1\" != \"version\" ]; then exit 9; fi\nprintf 'sink {version}\\n'\n"
        )
    }

    fn release_archive(script: &[u8]) -> TestResult<Vec<u8>> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(script.len())?);
        header.set_mode(0o755);
        header.set_cksum();
        archive.append_data(&mut header, BINARY_NAME, Cursor::new(script))?;

        let server = b"test archive server binary that must never be installed";
        let mut server_header = tar::Header::new_gnu();
        server_header.set_size(u64::try_from(server.len())?);
        server_header.set_mode(0o755);
        server_header.set_cksum();
        archive.append_data(
            &mut server_header,
            "sink-server",
            Cursor::new(server.as_slice()),
        )?;
        let encoder = archive.into_inner()?;
        Ok(encoder.finish()?)
    }

    async fn metadata_server(version: &str, asset_names: &[&str]) -> TestResult<TestServer> {
        let version = version.to_owned();
        let asset_names = asset_names
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        TestServer::spawn(move |base_url| {
            let assets = asset_names
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    json!({
                        "name": name,
                        "url": format!("{base_url}/unused/{index}"),
                    })
                })
                .collect::<Vec<_>>();
            let release = github_release_json(&version, assets)?;
            Ok(HashMap::from([(
                "/repos/ptrstovka/sink/releases/latest".to_owned(),
                release,
            )]))
        })
        .await
    }

    async fn install_server(
        version: &str,
        script: &[u8],
        digest_override: Option<&str>,
    ) -> TestResult<TestServer> {
        let version = version.to_owned();
        let archive = release_archive(script)?;
        let digest = digest_override.map_or_else(
            || format!("sha256:{:x}", Sha256::digest(&archive)),
            str::to_owned,
        );
        let checksum = format!("{:x}", Sha256::digest(&archive));

        TestServer::spawn(move |base_url| {
            let asset_name = format!("sink-v{version}-macos-arm64.tar.gz");
            let assets = vec![
                json!({
                    "name": asset_name,
                    "url": format!("{base_url}/download/archive"),
                    "digest": digest,
                }),
                json!({
                    "name": CHECKSUM_ASSET_NAME,
                    "url": format!("{base_url}/download/SHA256SUMS"),
                }),
            ];
            let release = github_release_json(&version, assets)?;
            let sums = format!("{checksum}  {asset_name}\n").into_bytes();
            Ok(HashMap::from([
                (
                    "/repos/ptrstovka/sink/releases/latest".to_owned(),
                    release.clone(),
                ),
                (
                    format!("/repos/ptrstovka/sink/releases/tags/v{version}"),
                    release,
                ),
                ("/download/archive".to_owned(), archive),
                ("/download/SHA256SUMS".to_owned(), sums),
            ]))
        })
        .await
    }

    fn github_release_json(version: &str, assets: Vec<serde_json::Value>) -> TestResult<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({
            "tag_name": format!("v{version}"),
            "created_at": "2026-01-01T00:00:00Z",
            "name": format!("Sink v{version}"),
            "body": "test release",
            "html_url": "https://example.invalid/release",
            "assets": assets,
        }))?)
    }

    struct TestServer {
        base_url: String,
        request_paths: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl TestServer {
        async fn spawn(
            build_routes: impl FnOnce(&str) -> TestResult<HashMap<String, Vec<u8>>>,
        ) -> TestResult<Self> {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let base_url = format!("http://{}", listener.local_addr()?);
            let state = Arc::new(TestServerState {
                routes: build_routes(&base_url)?,
                request_paths: Arc::new(Mutex::new(Vec::new())),
            });
            let request_paths = Arc::clone(&state.request_paths);
            let app = Router::new()
                .fallback(any(test_server_handler))
                .with_state(state);
            let task = tokio::spawn(async move {
                drop(axum::serve(listener, app).await);
            });
            Ok(Self {
                base_url,
                request_paths,
                task,
            })
        }

        async fn request_paths(&self) -> Vec<String> {
            self.request_paths.lock().await.clone()
        }

        async fn request_count(&self) -> usize {
            self.request_paths.lock().await.len()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct TestServerState {
        routes: HashMap<String, Vec<u8>>,
        request_paths: Arc<Mutex<Vec<String>>>,
    }

    async fn test_server_handler(
        State(state): State<Arc<TestServerState>>,
        uri: Uri,
    ) -> Response<Body> {
        let path = uri.path().to_owned();
        state.request_paths.lock().await.push(path.clone());
        match state.routes.get(&path) {
            Some(body) => Response::new(Body::from(body.clone())),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::NOT_FOUND;
                response
            }
        }
    }
}
