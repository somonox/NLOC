mod commands;
mod crypto;

mod network;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                network::run_udp_server(handle).await;
            });

            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(commands::HostPublicAddress(std::sync::Mutex::new(None)))
        .manage(commands::PendingShardState(std::sync::Mutex::new(
            Vec::new(),
        )))
        .invoke_handler(tauri::generate_handler![
            commands::create_and_save_shards,
            commands::get_saved_secrets,
            commands::get_host_info,
            commands::add_trusted_node,
            commands::get_trusted_nodes,
            commands::get_pending_shards,
            commands::backup_shard_c
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
