use std::process::Command;

use regex::Regex;

use crate::ReauthfiError;

pub struct WifiController;

impl WifiController {
    pub fn wifi_device() -> Result<String, ReauthfiError> {
        let output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
            .map_err(ReauthfiError::from)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let re_block = Regex::new(r"(?s)Hardware Port:\s*(Wi-Fi|AirPort).*?Device:\s*([^\s]+)")
            .map_err(|_| ReauthfiError::NotFound)?;

        re_block
            .captures(&stdout)
            .and_then(|caps| caps.get(2).map(|m| m.as_str().to_string()))
            .ok_or(ReauthfiError::NotFound)
    }

    pub fn reset_wifi(device: &str) -> Result<(), ReauthfiError> {
        Command::new("networksetup")
            .args(["-setairportpower", device, "off"])
            .status()
            .map_err(ReauthfiError::from)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(ReauthfiError::CommandFailed(format!(
                        "setairportpower off failed ({})",
                        status
                    )))
                }
            })?;

        std::thread::sleep(std::time::Duration::from_secs(2));

        Command::new("networksetup")
            .args(["-setairportpower", device, "on"])
            .status()
            .map_err(ReauthfiError::from)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(ReauthfiError::CommandFailed(format!(
                        "setairportpower on failed ({})",
                        status
                    )))
                }
            })?;

        Ok(())
    }
}
