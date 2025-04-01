use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use sysinfo::System;
use tao::{
    event::Event,
    event_loop::{ControlFlow, EventLoopBuilder},
};
use thiserror::Error;
use tokio;
use tray_icon::{
    TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

const ICON_BYTES: &[u8] = include_bytes!("resources/icon.png");
const FAVICON_SVG: &[u8] = include_bytes!("resources/favicon.svg");
const HTML_TEMPLATE: &str = include_str!("resources/index.html");
const GITHUB_REPO_URL: &str = "https://github.com/harshdoesdev/odineye";
const LOCAL_SERVER_ADDR: &str = "127.0.0.1:58638";

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Image processing error: {0}")]
    Image(#[from] image::error::ImageError),

    #[error("Tray icon error: {0}")]
    TrayIcon(String),

    #[error("Menu error: {0}")]
    Menu(String),

    #[error("System time error: {0}")]
    Time(#[from] std::time::SystemTimeError),

    #[error("Event proxy error: {0}")]
    EventProxy(String),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    #[error("Browser open error: {0}")]
    BrowserOpen(String),
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
enum UserEvent {
    MenuEvent(tray_icon::menu::MenuEvent),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SystemStatus {
    status: String,
    warnings: Vec<String>,
    timestamp: u64,
}

struct SystemCheck {
    status: Arc<Mutex<SystemStatus>>,
}

impl SystemCheck {
    fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(SystemStatus {
                status: "Idle".to_string(),
                warnings: vec![],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(AppError::Time)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_secs(),
            })),
        }
    }

    fn update_status(&self, new_status: &str, warnings: Vec<String>) -> Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| AppError::Server("Failed to lock status mutex".into()))?;
        status.status = new_status.to_string();
        status.warnings = warnings;
        status.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(())
    }

    fn run_checks(&self) -> Result<SystemStatus> {
        self.update_status("Running checks...", vec![])?;
        let mut warnings = vec![];
        let sys = System::new_all();

        if cfg!(target_os = "macos") {
            let output = std::process::Command::new("system_profiler")
                .arg("SPDisplaysDataType")
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let display_count = stdout.matches("Resolution").count();
            if display_count > 1 {
                warnings.push(format!("Multiple displays detected ({})", display_count));
            }
        }

        let sharing_processes = [
            "screensharing",
            "zoom",
            "teamviewer",
            "vnc",
            "anydesk",
            "discord",
            "teams",
        ];
        for process in sys.processes().values() {
            let name = process.name().to_string_lossy().to_lowercase();
            if sharing_processes.iter().any(|&p| name.contains(p)) {
                warnings.push(format!("Screen sharing detected: {}", name));
            }
        }

        let status = if warnings.is_empty() {
            "All checks passed"
        } else {
            "Issues detected"
        };

        let result = SystemStatus {
            status: status.to_string(),
            warnings: warnings.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        self.update_status(&result.status, warnings)?;
        Ok(result)
    }
}

async fn get_status(State(check_system): State<Arc<SystemCheck>>) -> Result<Json<SystemStatus>> {
    let status = check_system
        .status
        .lock()
        .map_err(|_| AppError::Server("Failed to lock status mutex".into()))?
        .clone();
    Ok(Json(status))
}

async fn run_new_scan(State(check_system): State<Arc<SystemCheck>>) -> Result<Json<SystemStatus>> {
    let result = tokio::task::spawn_blocking(move || check_system.run_checks()).await??;

    Ok(Json(result))
}

async fn get_html() -> axum::response::Html<String> {
    axum::response::Html(HTML_TEMPLATE.to_string())
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
        let body = Json(serde_json::json!({
            "error": self.to_string(),
        }));

        (status, body).into_response()
    }
}

async fn get_favicon() -> Result<impl axum::response::IntoResponse> {
    let body = axum::body::Bytes::from_static(FAVICON_SVG);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_str("image/svg+xml")
            .map_err(|_| AppError::Server("Failed to create content type header".into()))?,
    );

    Ok((headers, body))
}

async fn start_server(check_system: Arc<SystemCheck>) -> Result<()> {
    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/status", post(run_new_scan))
        .route("/", get(get_html))
        .route("/favicon.svg", get(get_favicon))
        .with_state(check_system);

    let listener = tokio::net::TcpListener::bind(LOCAL_SERVER_ADDR).await?;
    let addr = listener.local_addr()?;

    println!("Server started at {}", addr.to_string());

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Server(format!("Server error: {}", e)))?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let check_system = Arc::new(SystemCheck::new());

    let server_check_system = check_system.clone();

    if let Err(e) = server_check_system.run_checks() {
        eprintln!("Warning: Initial system check failed: {}", e);
    }

    tokio::spawn(async move {
        if let Err(e) = start_server(server_check_system).await {
            eprintln!("Server error: {}", e);
        }
    });

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        if let Err(e) = proxy
            .send_event(UserEvent::MenuEvent(event))
            .map_err(|_| AppError::EventProxy("Failed to send event".into()))
        {
            eprintln!("Event proxy error: {}", e);
        }
    }));

    let tray_menu = Menu::new();
    let about_i = MenuItem::new("About OdinEye", true, None);
    let run_tests_i = MenuItem::new("Run Tests", true, None);
    let quit_i = MenuItem::new("Quit", true, None);

    tray_menu
        .append_items(&[
            &about_i,
            &PredefinedMenuItem::separator(),
            &run_tests_i,
            &quit_i,
        ])
        .map_err(|e| AppError::Menu(e.to_string()))?;

    let mut tray_icon = None;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(tao::event::StartCause::Init) => match load_icon() {
                Ok(icon) => {
                    match TrayIconBuilder::new()
                        .with_menu(Box::new(tray_menu.clone()))
                        .with_tooltip("OdinEye - Interview Check")
                        .with_icon(icon)
                        .build()
                    {
                        Ok(icon) => tray_icon = Some(icon),
                        Err(e) => eprintln!("Failed to build tray icon: {}", e),
                    }
                }
                Err(e) => eprintln!("Failed to load icon: {}", e),
            },

            Event::UserEvent(UserEvent::MenuEvent(event)) => {
                if event.id == about_i.id() {
                    if let Err(e) = open::that(GITHUB_REPO_URL)
                        .map_err(|e| AppError::BrowserOpen(e.to_string()))
                    {
                        eprintln!("Failed to open browser: {}", e);
                    }
                }

                if event.id == run_tests_i.id() {
                    let check_clone = Arc::clone(&check_system);
                    std::thread::spawn(move || {
                        if let Err(e) = check_clone.run_checks() {
                            eprintln!("Failed to run checks: {}", e);
                        }
                    });

                    if let Err(e) = open::that(format!("http://{}", LOCAL_SERVER_ADDR))
                        .map_err(|e| AppError::BrowserOpen(e.to_string()))
                    {
                        eprintln!("Failed to open browser: {}", e);
                    }
                }

                if event.id == quit_i.id() {
                    tray_icon.take();
                    *control_flow = ControlFlow::Exit;
                }
            }

            _ => {}
        }
    });
}

fn load_icon() -> Result<tray_icon::Icon> {
    let (icon_rgba, icon_width, icon_height) = {
        let image = image::load_from_memory(ICON_BYTES)?;
        let image = image.into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    tray_icon::Icon::from_rgba(icon_rgba, icon_width, icon_height)
        .map_err(|e| AppError::TrayIcon(e.to_string()))
}
