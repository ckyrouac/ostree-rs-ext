//! Fork bootc as a subprocess

use anyhow::Result;

// check if the bootc exe is present
pub(crate) fn exe_exists() -> Result<bool> {
    // mount image and check if bootc exists at /usr/bin/bootc
    Ok(true)
}

pub(crate) async fn install(
    imgref: &crate::container::ImageReference,
    sysroot: String,
    stateroot: String,
) -> Result<()> {
    let mut subproc = std::process::Command::new("bootc");
    let imgref = imgref.to_string();

    println!("**** imgref: {}", imgref);
    println!("**** sysroot: {}", sysroot);
    println!("**** stateroot: {}", stateroot);

    let st = std::process::Command::new("bootc")
        .args([
            "install",
            "to-filesystem",
            "--disable-selinux",
            "--source-imgref",
            imgref.as_str(),
            sysroot.as_str(),
        ])
        .status()?;
    Ok(())
}
