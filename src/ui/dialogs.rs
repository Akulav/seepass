//! Settings page and modal dialogs (delete, change password, backups, import).

use std::path::PathBuf;

use eframe::egui::{self, RichText};
use seepass::crypto::{KdfParams, MasterKey};
use seepass::vault::{self, VaultData};
use seepass::{strength, Result};
use zeroize::Zeroizing;

use super::task::{self, Task};
use super::vault_view::{Nav, Unlocked};
use super::widgets::{self, DANGER};
use super::{Next, Shared};

pub enum Dialog {
    ConfirmDelete {
        id: String,
        title: String,
    },
    /// The editor has unsaved changes and the user tried to leave it.
    DiscardChanges(Nav),
    ChangePassword(PasswordForm, Option<Task<Result<MasterKey>>>),
    ExportBackup {
        path: PathBuf,
        form: PasswordForm,
        task: Option<Task<Result<()>>>,
    },
    ImportBackup {
        path: PathBuf,
        password: Zeroizing<String>,
        show: bool,
        error: Option<String>,
        task: Option<Task<Result<VaultData>>>,
    },
    DestroyVault {
        typed: String,
    },
}

#[derive(Default)]
pub struct PasswordForm {
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    confirm: Zeroizing<String>,
    show: bool,
    strong: bool,
    error: Option<String>,
}

/// Ask for a backup file, then open the import dialog for it.
pub fn pick_backup_import(u: &mut Unlocked) {
    if let Some(path) = rfd::FileDialog::new()
        .set_title("Import SeePass backup")
        .add_filter("SeePass vault", &["seepass"])
        .add_filter("All files", &["*"])
        .pick_file()
    {
        u.dialog =
            Some(Dialog::ImportBackup { path, password: Zeroizing::default(), show: false, error: None, task: None });
    }
}

fn section(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(title).small().strong().weak());
    widgets::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 4.0;
        add(ui);
    });
    ui.add_space(10.0);
}

/// One setting: name and a short hint on the left, its control lined up on the right edge.
fn setting_row(ui: &mut egui::Ui, label: &str, hint: &str, control: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(44.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add_space(4.0);
            ui.label(label);
            if !hint.is_empty() {
                ui.label(RichText::new(hint).small().weak());
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), control);
    });
}

/// Same-width buttons on the right of a settings row.
fn row_button(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) -> egui::Response {
    ui.add(egui::Button::new(text).min_size(egui::vec2(230.0, 32.0)))
}

/// The settings page, shown in the main area in place of an entry. Three tabs, each short enough to fit without
/// scrolling.
pub fn settings_page(ui: &mut egui::Ui, u: &mut Unlocked, shared: &mut Shared) {
    let ctx = ui.ctx().clone();
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new("Settings").heading().strong());
            ui.label(RichText::new("Changes are saved right away.").small().weak());
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(egui::Button::new("✖ Close").min_size(egui::vec2(0.0, 32.0))).clicked() {
                u.settings_open = false;
            }
        });
    });
    ui.add_space(10.0);
    widgets::tab_strip(ui, &["General", "Backup", "Vault file"], &mut u.settings_tab);
    ui.add_space(10.0);
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        if u.settings_tab == 0 {
            section(ui, "APPEARANCE", |ui| {
                setting_row(ui, "Theme", "Windows 11 dark or light", |ui| {
                    let mut dark = shared.settings.dark_mode;
                    // Right-to-left, so Light is added first.
                    if widgets::toggle_button(ui, !dark, "☀ Light").clicked() {
                        dark = false;
                    }
                    if widgets::toggle_button(ui, dark, "🌙 Dark").clicked() {
                        dark = true;
                    }
                    if dark != shared.settings.dark_mode {
                        shared.settings.dark_mode = dark;
                        widgets::apply_style(&ctx, dark);
                        shared.save_settings();
                    }
                });
            });

            section(ui, "SECURITY", |ui| {
                setting_row(ui, "Auto-lock after", "Locks the vault when you step away. 0 = never", |ui| {
                    let mut lock_min = shared.settings.auto_lock_secs / 60;
                    let r =
                        ui.add_sized([110.0, 30.0], egui::DragValue::new(&mut lock_min).range(0..=240).suffix(" min"));
                    if r.changed() {
                        shared.settings.auto_lock_secs = lock_min * 60;
                        shared.save_settings();
                    }
                });
                setting_row(
                    ui,
                    "Clear clipboard after",
                    "Copied passwords are wiped from the clipboard. 0 = never",
                    |ui| {
                        let r = ui.add_sized(
                            [110.0, 30.0],
                            egui::DragValue::new(&mut shared.settings.clipboard_clear_secs).range(0..=600).suffix(" s"),
                        );
                        if r.changed() {
                            shared.save_settings();
                        }
                    },
                );
                let p = u.vault.kdf_params();
                let mem = if p.m_cost_kib >= 1024 {
                    format!("{} MiB", p.m_cost_kib / 1024)
                } else {
                    format!("{} KiB", p.m_cost_kib)
                };
                let passes = if p.t_cost == 1 { "1 pass".to_string() } else { format!("{} passes", p.t_cost) };
                let kdf = format!("Key derivation: Argon2id, {mem}, {passes}");
                setting_row(ui, "Master password", &kdf, |ui| {
                    if row_button(ui, "🔑 Change master password...").clicked() {
                        u.dialog = Some(Dialog::ChangePassword(PasswordForm::default(), None));
                    }
                });
            });
        }
        if u.settings_tab == 1 {
            section(ui, "BACKUP & IMPORT", |ui| {
                setting_row(
                    ui,
                    "Export",
                    "Save a copy of the vault, encrypted with a password you choose for it",
                    |ui| {
                        if row_button(ui, "⬆ Export encrypted backup...").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Export encrypted backup")
                                .set_file_name("seepass-backup.seepass")
                                .add_filter("SeePass vault", &["seepass"])
                                .save_file()
                            {
                                u.dialog =
                                    Some(Dialog::ExportBackup { path, form: PasswordForm::default(), task: None });
                            }
                        }
                    },
                );
                ui.separator();
                setting_row(ui, "Import", "Merge the entries of a backup or another vault into this one", |ui| {
                    if row_button(ui, "⬇ Import / merge backup...").clicked() {
                        pick_backup_import(u);
                    }
                });
            });
        }
        if u.settings_tab == 2 {
            section(ui, "VAULT FILE", |ui| {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(RichText::new(u.vault.path().display().to_string()).small().monospace()).wrap(),
                );
                ui.label(
                    RichText::new(format!(
                        "Previous version kept as {}",
                        vault::backup_path(u.vault.path()).file_name().unwrap_or_default().to_string_lossy()
                    ))
                    .small()
                    .weak(),
                );
                ui.add_space(4.0);
            });

            ui.label(RichText::new("DANGER ZONE").small().strong().color(DANGER));
            widgets::banner(DANGER).show(ui, |ui| {
                ui.set_width(ui.available_width());
                setting_row(
                    ui,
                    "Delete this vault",
                    "Removes the vault file and its backup. This can't be undone.",
                    |ui| {
                        if row_button(ui, RichText::new("🗑 Delete this vault...").color(DANGER)).clicked() {
                            u.dialog = Some(Dialog::DestroyVault { typed: String::new() });
                        }
                    },
                );
            });
        }
    });
}
pub fn show_dialog(ctx: &egui::Context, u: &mut Unlocked, shared: &mut Shared) -> Option<Next> {
    let dialog = u.dialog.as_mut()?;
    let mut close = false;
    let mut next = None;
    let mut after: Option<Nav> = None;

    let modal = egui::Modal::new(egui::Id::new("dialog")).show(ctx, |ui| {
        ui.set_width(380.0);
        match dialog {
            Dialog::ConfirmDelete { id, title } => {
                ui.heading("Delete entry?");
                ui.label(format!("\"{title}\" will be removed from the vault. You can undo this for a few seconds."));
                ui.horizontal(|ui| {
                    let del = ui.button(RichText::new("🗑 Delete").color(DANGER));
                    if del.clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        match u.vault.remove(id) {
                            Ok(Some(entry)) => {
                                u.undo = Some((entry, std::time::Instant::now()));
                                after = Some(Nav::Select(None));
                            }
                            Ok(None) => {}
                            Err(e) => shared.error(format!("Could not delete: {e}")),
                        }
                        close = true;
                    }
                    close |= ui.button("Cancel").clicked();
                });
            }

            Dialog::DiscardChanges(nav) => {
                ui.heading("Discard changes?");
                ui.label("This entry has unsaved changes.");
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Discard").color(DANGER)).clicked() {
                        after = Some(nav.clone());
                        close = true;
                    }
                    close |= ui.button("Keep editing").clicked();
                });
            }

            Dialog::ChangePassword(form, task) => {
                if let Some(result) = task::take(task) {
                    match result.and_then(|key| u.vault.set_key(key)) {
                        Ok(()) => {
                            shared.toast("Master password changed");
                            close = true;
                        }
                        Err(e) => form.error = Some(e.to_string()),
                    }
                }
                ui.heading("Change master password");
                widgets::secret_field(ui, &mut form.current, &mut form.show, "Current master password");
                widgets::secret_field(ui, &mut form.new, &mut form.show, "New master password");
                widgets::strength_meter(ui, &form.new);
                widgets::secret_field(ui, &mut form.confirm, &mut form.show, "Repeat new master password");
                ui.checkbox(&mut form.strong, "Extra-strong key derivation (256 MiB)");
                widgets::error_label(ui, &form.error);
                let busy = task.is_some();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, egui::Button::new("Change")).clicked() {
                        form.error = validate_new(&form.new, &form.confirm, true);
                        if form.error.is_none() {
                            // Verify the current password and derive the new key off-thread.
                            let path = u.vault.path().to_path_buf();
                            let (cur, new) = (form.current.clone(), form.new.clone());
                            let params = if form.strong { KdfParams::STRONG } else { KdfParams::STANDARD };
                            *task = Some(Task::spawn(ui.ctx(), move || {
                                let bytes = std::fs::read(&path)?;
                                seepass::crypto::open(&cur, &bytes)
                                    .map_err(|_| seepass::Error::Kdf("the current password is wrong".into()))?;
                                MasterKey::derive_new(&new, params)
                            }));
                        }
                    }
                    close |= ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                    if busy {
                        ui.spinner();
                    }
                });
            }

            Dialog::ExportBackup { path, form, task } => {
                if let Some(result) = task::take(task) {
                    match result {
                        Ok(()) => {
                            shared.toast(format!("Backup written to {}", path.display()));
                            close = true;
                        }
                        Err(e) => form.error = Some(e.to_string()),
                    }
                }
                ui.heading("Export encrypted backup");
                ui.label(RichText::new(path.display().to_string()).small().monospace());
                ui.label("Choose a password for the backup. It can differ from your master password.");
                widgets::secret_field(ui, &mut form.new, &mut form.show, "Backup password");
                widgets::strength_meter(ui, &form.new);
                widgets::secret_field(ui, &mut form.confirm, &mut form.show, "Repeat backup password");
                widgets::error_label(ui, &form.error);
                let busy = task.is_some();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, egui::Button::new("Export")).clicked() {
                        form.error = validate_new(&form.new, &form.confirm, false);
                        if form.error.is_none() {
                            let (dest, pw, params, data) =
                                (path.clone(), form.new.clone(), u.vault.kdf_params(), u.vault.snapshot());
                            *task = Some(Task::spawn(ui.ctx(), move || vault::write_backup(&dest, &pw, params, &data)));
                        }
                    }
                    close |= ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                    if busy {
                        ui.spinner();
                    }
                });
            }

            Dialog::ImportBackup { path, password, show, error, task } => {
                if let Some(result) = task::take(task) {
                    match result.and_then(|data| u.vault.merge(data)) {
                        Ok(r) => {
                            shared.toast(format!(
                                "Imported: {} added, {} updated, {} unchanged",
                                r.added, r.updated, r.unchanged
                            ));
                            close = true;
                        }
                        Err(e) => *error = Some(e.to_string()),
                    }
                }
                ui.heading("Import / merge backup");
                ui.label(RichText::new(path.display().to_string()).small().monospace());
                ui.label("New entries are added; entries that exist in both keep the most recently edited copy.");
                widgets::secret_field(ui, password, show, "Backup password");
                widgets::error_label(ui, error);
                let busy = task.is_some();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy && !password.is_empty(), egui::Button::new("Import")).clicked() {
                        let (src, pw) = (path.clone(), password.clone());
                        *task = Some(Task::spawn(ui.ctx(), move || vault::Vault::read_backup(&src, &pw)));
                    }
                    close |= ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                    if busy {
                        ui.spinner();
                    }
                });
            }

            Dialog::DestroyVault { typed } => {
                ui.heading(RichText::new("Delete this vault?").color(DANGER));
                ui.label(
                    "This permanently deletes the vault file and its automatic backup. \
                     Without an exported backup, the entries are gone for good.",
                );
                ui.label("Type DELETE to confirm:");
                ui.text_edit_singleline(typed);
                ui.horizontal(|ui| {
                    let ok = typed.as_str() == "DELETE";
                    if ui.add_enabled(ok, egui::Button::new(RichText::new("Delete vault").color(DANGER))).clicked() {
                        match vault::destroy(u.vault.path()) {
                            Ok(()) => {
                                shared.toast("Vault deleted");
                                next = Some(Next::Setup);
                            }
                            Err(e) => shared.error(format!("Could not delete vault: {e}")),
                        }
                        close = true;
                    }
                    close |= ui.button("Cancel").clicked();
                });
            }
        }
    });

    // Escape / click outside closes the dialog, except while work is running.
    let busy = match &u.dialog {
        Some(Dialog::ChangePassword(_, t)) => t.is_some(),
        Some(Dialog::ExportBackup { task, .. }) => task.is_some(),
        Some(Dialog::ImportBackup { task, .. }) => task.is_some(),
        _ => false,
    };
    if close || (modal.should_close() && !busy) {
        u.dialog = None;
    }
    if let Some(nav) = after {
        u.apply(nav);
    }
    next
}

fn validate_new(new: &str, confirm: &str, is_master: bool) -> Option<String> {
    if is_master {
        if let Some(p) = strength::master_password_problem(new) {
            return Some(p);
        }
    } else if new.chars().count() < strength::MIN_MASTER_LENGTH {
        return Some(format!("Use at least {} characters.", strength::MIN_MASTER_LENGTH));
    }
    (new != confirm).then(|| "The passwords do not match.".into())
}
