mod dml;
mod gui;
mod injector;
mod kinp;
mod pipe_reader;
mod schema;
mod wad;

use gui::PacketLoggerApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("Wizard101 Packet Logger"),
        ..Default::default()
    };

    eframe::run_native(
        "Wizard101 Packet Logger",
        options,
        Box::new(|_cc| Ok(Box::new(PacketLoggerApp::new()))),
    )
}
