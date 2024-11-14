//! Fork skopeo as a subprocess

use super::ImageReference;
use anyhow::{Context, Result};
use cap_std_ext::cmdext::CapStdExtCommandExt;
use containers_image_proxy::oci_spec::image as oci_image;
use fn_error_context::context;
use io_lifetimes::OwnedFd;
use rustix::path::Arg;
use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::str::FromStr;
use std::collections::HashMap;
use tokio::process::Command;

// See `man containers-policy.json` and
// https://github.com/containers/image/blob/main/signature/policy_types.go
// Ideally we add something like `skopeo pull --disallow-insecure-accept-anything`
// but for now we parse the policy.
const POLICY_PATH: &str = "/etc/containers/policy.json";
const INSECURE_ACCEPT_ANYTHING: &str = "insecureAcceptAnything";

#[derive(Deserialize)]
struct PolicyEntry {
    #[serde(rename = "type")]
    ty: String,
}
#[derive(Deserialize)]
struct ContainerPolicy {
    default: Option<Vec<PolicyEntry>>,
}

impl ContainerPolicy {
    fn is_default_insecure(&self) -> bool {
        if let Some(default) = self.default.as_deref() {
            match default.split_first() {
                Some((v, &[])) => v.ty == INSECURE_ACCEPT_ANYTHING,
                _ => false,
            }
        } else {
            false
        }
    }
}

pub(crate) fn container_policy_is_default_insecure() -> Result<bool> {
    let r = std::io::BufReader::new(std::fs::File::open(POLICY_PATH)?);
    let policy: ContainerPolicy = serde_json::from_reader(r)?;
    Ok(policy.is_default_insecure())
}

/// Create a Command builder for skopeo.
pub(crate) fn new_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new("skopeo");
    cmd.stdin(Stdio::null());
    cmd
}

/// Spawn the child process
pub(crate) fn spawn(mut cmd: Command) -> Result<tokio::process::Child> {
    let cmd = cmd.stdin(Stdio::null()).stderr(Stdio::piped());
    cmd.spawn().context("Failed to exec skopeo")
}

/// Use skopeo to inspect an image for it's labels.
#[context("Skopeo inspect")]
pub(crate) async fn labels(
    img: &ImageReference,
    authfile: Option<&Path>,
) -> Result<HashMap<String, String>> {
    let mut cmd = new_cmd();
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.arg("inspect");
    cmd.arg("--format");
    cmd.arg("{{json .Labels}}");
    cmd.arg(img.to_string());

    if let Some(authfile) = authfile {
        cmd.arg("--authfile");
        cmd.arg(authfile);
    }

    let mut cmd = tokio::process::Command::from(cmd);
    cmd.kill_on_drop(true);
    let proc = super::skopeo::spawn(cmd)?;
    let output = proc.wait_with_output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("skopeo inspect failed: {}\n", stderr));
    }

    let output_json = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(output_json.as_str()?)?;

    let map: HashMap<String, String> = result.as_object()
        .expect("Expected a JSON object")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("Expected a string").to_string()))
        .collect();

    Ok(map)
}

/// Use skopeo to copy a container image.
#[context("Skopeo copy")]
pub(crate) async fn copy(
    src: &ImageReference,
    dest: &ImageReference,
    authfile: Option<&Path>,
    add_fd: Option<(std::sync::Arc<OwnedFd>, i32)>,
    progress: bool,
) -> Result<oci_image::Digest> {
    let digestfile = tempfile::NamedTempFile::new()?;
    let mut cmd = new_cmd();
    cmd.arg("copy");
    if !progress {
        cmd.stdout(std::process::Stdio::null());
    }
    cmd.arg("--digestfile");
    cmd.arg(digestfile.path());
    if let Some((add_fd, n)) = add_fd {
        cmd.take_fd_n(add_fd, n);
    }
    if let Some(authfile) = authfile {
        cmd.arg("--authfile");
        cmd.arg(authfile);
    }
    cmd.args(&[src.to_string(), dest.to_string()]);
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.kill_on_drop(true);
    let proc = super::skopeo::spawn(cmd)?;
    let output = proc.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("skopeo failed: {}\n", stderr));
    }
    let mut digestfile = digestfile.into_file();
    let mut r = String::new();
    digestfile.read_to_string(&mut r)?;
    Ok(oci_image::Digest::from_str(r.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Default value as of the Fedora 34 containers-common-1-21.fc34.noarch package.
    const DEFAULT_POLICY: &str = indoc::indoc! {r#"
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports":
            {
                "docker-daemon":
                    {
                        "": [{"type":"insecureAcceptAnything"}]
                    }
            }
    }
    "#};

    // Stripped down copy from the manual.
    const REASONABLY_LOCKED_DOWN: &str = indoc::indoc! { r#"
    {
        "default": [{"type": "reject"}],
        "transports": {
            "dir": {
                "": [{"type": "insecureAcceptAnything"}]
            },
            "atomic": {
                "hostname:5000/myns/official": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/path/to/official-pubkey.gpg"
                    }
                ]
            }
        }
    }
    "#};

    #[test]
    fn policy_is_insecure() {
        let p: ContainerPolicy = serde_json::from_str(DEFAULT_POLICY).unwrap();
        assert!(p.is_default_insecure());
        for &v in &["{}", REASONABLY_LOCKED_DOWN] {
            let p: ContainerPolicy = serde_json::from_str(v).unwrap();
            assert!(!p.is_default_insecure());
        }
    }

    #[tokio::test]
    async fn label_test() {
        let img = ImageReference::try_from("docker://quay.io/centos-bootc/centos-bootc:stream9");
        let lbls = labels(&img.unwrap(), None).await;
        let lbls_hash = lbls.unwrap_or_else(|e| panic!("Failed to get labels: {}", e));
        assert!(lbls_hash.contains_key("containers.bootc"))
    }
}
