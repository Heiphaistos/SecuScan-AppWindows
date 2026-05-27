mod api;
mod commands;
mod engine;
mod error;
mod export;
mod models;
mod parsers;
mod security;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // Scan
            commands::start_scan,
            commands::cancel_scan,
            // AI
            commands::request_ai_fix,
            commands::build_clipboard_prompt,
            commands::batch_ai_fix,
            commands::apply_patch,
            // Export
            commands::export_json,
            commands::export_csv,
            commands::export_markdown,
            commands::export_txt,
            commands::export_html,
            commands::save_report_to_file,
            // Keys
            commands::save_api_key,
            commands::delete_api_key,
            commands::get_key_status,
            commands::save_antigravity_endpoint,
            // Info
            commands::get_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecuScan AI");
}
