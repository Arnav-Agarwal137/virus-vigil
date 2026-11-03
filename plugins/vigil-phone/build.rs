// No commands are exposed to the page directly: the app's own `phone` command calls the
// Kotlin side through `call()`, so the page needs no plugin permissions.
const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
