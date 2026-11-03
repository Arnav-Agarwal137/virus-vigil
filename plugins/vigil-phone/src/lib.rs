//! Virus Vigil's phone-only side. The Kotlin class `PhonePlugin` does everything an
//! Android app can read about the phone; this crate only registers it and forwards calls.
//! On the laptop the plugin loads but every call answers "only on the phone".

use serde_json::Value;
use tauri::{
    plugin::{Builder, TauriPlugin},
    AppHandle, Runtime,
};

#[cfg(target_os = "android")]
use tauri::Manager;

#[cfg(target_os = "android")]
struct Phone<R: Runtime>(tauri::plugin::PluginHandle<R>);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vigil-phone")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                let handle = _api.register_android_plugin("com.arnav.vigilphone", "PhonePlugin")?;
                _app.manage(Phone(handle));
            }
            Ok(())
        })
        .build()
}

/// Run one Kotlin command and return its JSON answer.
pub fn call<R: Runtime>(app: &AppHandle<R>, cmd: &str, args: Value) -> Result<Value, String> {
    #[cfg(target_os = "android")]
    {
        let phone = app.try_state::<Phone<R>>().ok_or("the phone part did not load")?;
        return phone.0.run_mobile_plugin::<Value>(cmd, args).map_err(|e| e.to_string());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, cmd, args);
        Err("only on the phone".into())
    }
}
