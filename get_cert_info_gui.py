#!/usr/bin/env python3

"""
Утилита анализа и экспорта сертификатов X.509.
Поддерживает переключение тем: Светлая, Тёмная, Системная (с автосохранением в QSettings).
"""


from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ObjectIdentifier
from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QSettings,
    QSortFilterProxyModel,
    Qt,
    QThread,
    Signal,
)
from PySide6.QtGui import QAction, QActionGroup, QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStyle,
    QTableView,
    QVBoxLayout,
    QWidget,
)

APP_VERSION = "1.0.0b"
SUPPORTED_EXTENSIONS = {".cer", ".crt", ".pem", ".der"}

# --- Управляем темами управления ---


class ThemeMode(str, Enum):
    SYSTEM = "system"
    LIGHT = "light"
    DARK = "dark"


class ThemeManager(QObject):
    theme_applied = Signal()

    def __init__(self, app: QApplication):
        super().__init__()
        self._app = app
        self._settings = QSettings("SecurityTools", "CertAnalyzer")
        self._mode = ThemeMode(self._settings.value("ui/theme", ThemeMode.SYSTEM.value))

        # Слушаем смену темы на уровне ОС (Qt 6.5 и выше)
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(self._on_system_scheme_changed)


    @property
    def current_mode(self) -> ThemeMode:
        return self._mode

    def set_mode(self, mode: ThemeMode):
        self._mode = mode
        self._settings.setValue("ui/theme", mode.value)
        self.apply_theme()

    def _is_system_dark(self) -> bool:
        """Определяем, включена ли в опрерационной системе темная тема."""
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorScheme"):
            return hints.colorScheme() == Qt.ColorScheme.Dark
        # Резервная эвристическая проверка для старых окружений
        return self._app.palette().window().color().value() < 128

    def _create_dark_palette(self) -> QPalette:
        """Создаем современную сбалансированную темную палитру"""
        palette = QPalette()
        bg = QColor(32, 33, 36)
        surface = QColor(48, 49, 52)
        base = QColor(24, 24, 27)
        text = QColor(241, 243, 244)
        subtext = QColor(154, 160, 166)
        accent = QColor(100, 160, 255)
        disabled = QColor(90, 93, 97)

        palette.setColor(QPalette.ColorRole.Window, bg)
        palette.setColor(QPalette.ColorRole.WindowText, text)
        palette.setColor(QPalette.ColorRole.Base, base)
        palette.setColor(QPalette.ColorRole.AlternateBase, surface)
        palette.setColor(QPalette.ColorRole.ToolTipBase, surface)
        palette.setColor(QPalette.ColorRole.ToolTipText, text)
        palette.setColor(QPalette.ColorRole.Text, text)
        palette.setColor(QPalette.ColorRole.Text, text)
        palette.setColor(QPalette.ColorRole.Button, surface)
        palette.setColor(QPalette.ColorRole.ButtonText, text)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, accent)
        palette.setColor(QPalette.ColorRole.Highlight, accent)
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(20, 20, 20))

        # Устанавливаем состояния для неактивных элементов
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, disabled)
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, disabled)
        palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.WindowText, disabled)
        return palette


    def apply_theme(self):
        """Применяем выбранную тему ко всему приложению"""
        if self._mode == ThemeMode.DARK:
            should_be_dark = True
        elif self._mode == ThemeMode.LIGHT:
            should_be_dark = False
        else:
            should_be_dark = self._is_system_dark()

        if should_be_dark:
            self._app.setPalette(self._create_dark_palette())
        else:
            # Сбрасываем до стандартной светлой темы (Fusion)
            self._app.setPalette(self._app.style().standardPalette())

        self.theme_applied.emit()


    def _on_system_scheme_changed(self):
        """Данная функция срабатывает при смене темы в ОС."""
        if self._mode == ThemeMode.SYSTEM:
            self.apply_theme()


# --- Модели и обработка данных тут ---
class ExpirationStatus(IntEnum):
    ALL = 0
    VALID = 1
    EXPIRING_SOON = 2
    EXPIRED = 3


@dataclass(slots=True, frozen=True)
class CertRecord:
    fio: str
    position: str
    organization: str
    not_after: datetime
    thumbprint_sha1: str
    thumbprint_sha256: str
    file_path: str

    @property
    def not_after_str(self) -> str:
        return self.not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

    def to_csv_dict(self) -> dict[str, str]:
        return {
            "Ф.И.О.": self.fio,
            "Должность": self.position,
            "Организация": self.organization,
            "Действителен до": self.not_after_str,
            "Отпечаток SHA1": self.thumbprint_sha1,
            "Отпечаток SHA256": self.thumbprint_sha256,
        }


COLUMNS = [
    ("Ф.И.О.", "fio"),
    ("Должность", "position"),
    ("Организация", "organization"),
    ("Действителен до", "not_after"),
    ("Отпечаток SHA1", "thumbprint_sha1"),
    ("Отпечаток SHA256", "thumbprint_sha256"),
]


def _get_subject_attr(cert: x509.Certificate, oid: ObjectIdentifier) -> Optional[str]:
    attrs = cert.subject.get_attributes_for_oid(oid)
    if attrs and attrs[0].value is not None:
        return str(attrs[0].value)
    return None


def parse_certificate(cert_path: Path) -> CertRecord:
    cert_data = cert_path.read_bytes()

    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_data)

    sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()

    cn = _get_subject_attr(cert, NameOID.COMMON_NAME)
    sn = _get_subject_attr(cert, NameOID.SURNAME)
    gn = _get_subject_attr(cert, NameOID.GIVEN_NAME)
    org = _get_subject_attr(cert, NameOID.ORGANIZATION_NAME) or "Не указано"
    title = _get_subject_attr(cert, NameOID.TITLE) or "Не указано"

    if sn and gn:
        fio = f"{sn} {gn}"
    elif sn:
        fio = sn
    elif cn:
        fio = cn
    else:
        fio = "Не указано"

    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return CertRecord(
        fio=fio,
        position=title,
        organization=org,
        not_after=not_after,
        thumbprint_sha1=sha1,
        thumbprint_sha256=sha256,
        file_path=str(cert_path)
    )


class CertificateTableModel(QAbstractTableModel):
    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._records: List[CertRecord] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._records)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._records)):
            return None

        record = self._records[index.row()]
        col_name = COLUMNS[index.column()][1]

        if role == Qt.ItemDataRole.DisplayRole:
            if col_name == "not_after":
                return record.not_after_str
            return getattr(record, col_name)

        if role == Qt.ItemDataRole.UserRole:
            if col_name == "not_after":
                return record.not_after
            return getattr(record, col_name)

        if role == Qt.ItemDataRole.ToolTipRole:
            return f"Файл: {record.file_path}"

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][0]
        return None

    def add_records(self, new_records: List[CertRecord]):
        if not new_records:
            return
        first = len(self._records)
        last = first + len(new_records) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._records.extend(new_records)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._records.clear()
        self.endResetModel()


class CertificateFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._filter_status = ExpirationStatus.ALL
        self._filter_search = ""

    def set_expiration_filter(self, status: ExpirationStatus):
        self._filter_status = status
        self.invalidateFilter()

    def set_search_query(self, query: str):
        self._filter_search = query.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: CertificateTableModel = self.sourceModel()
        record = model._records[source_row]

        if self._filter_status != ExpirationStatus.ALL:
            now = datetime.now(timezone.utc)
            days_left = (record.not_after - now).days

            if self._filter_status == ExpirationStatus.VALID and days_left < 0:
                return False
            if self._filter_status == ExpirationStatus.EXPIRING_SOON and not (0 <= days_left <= 30):
                return False
            if self._filter_status == ExpirationStatus.EXPIRED and days_left >= 0:
                return False

        if not self._filter_search:
            return True

        return (
            self._filter_search in record.fio.lower()
            or self._filter_search in record.organization.lower()
            or self._filter_search in record.position.lower()
            or self._filter_search in record.thumbprint_sha1.lower()
            or self._filter_search in record.thumbprint_sha256.lower()
        )


class ScanWorker(QObject):
    progress = Signal(int, int)
    batch_ready = Signal(list)
    finished = Signal(int, int, bool)
    error = Signal(str)

    def __init__(self, source_dir: Path, output_csv: Path, batch_size: int = 50):
        super().__init__()
        self.source_dir = source_dir
        self.output_csv = output_csv
        self.batch_size = batch_size

    def run(self):
        try:
            cert_files = [
                p for p in self.source_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
            ]

            total = len(cert_files)
            if total == 0:
                self.finished.emit(0, 0, False)
                return

            self.output_csv.parent.mkdir(parents=True, exist_ok=True)

            success_count = 0
            error_count = 0
            batch: List[CertRecord] = []
            fieldnames = [c[0] for c in COLUMNS]

            with open(self.output_csv, mode="w", newline="", encoding="utf-8-sig") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=";")
                writer.writeheader()

                for i, cert_path in enumerate(cert_files, start=1):
                    if QThread.currentThread().isInterruptionRequested():
                        self.finished.emit(success_count, error_count, True)
                        return

                    try:
                        record = parse_certificate(cert_path)
                        writer.writerow(record.to_csv_dict())
                        batch.append(record)
                        success_count += 1
                    except Exception:
                        error_count += 1

                    if len(batch) >= self.batch_size:
                        self.batch_ready.emit(batch)
                        batch = []
                        self.progress.emit(i, total)

                if batch:
                    self.batch_ready.emit(batch)

                self.progress.emit(total, total)

            self.finished.emit(success_count, error_count, False)
        except Exception as e:
            self.error.emit(str(e))


# --- Главное окно ---

class MainWindow(QMainWindow):
    def __init__(self, theme_manager: ThemeManager):
        super().__init__()
        self.theme_manager = theme_manager
        self.setWindowTitle("Экспорт и анализ сертификатов X.509")
        self.resize(1150, 700)

        self.thread: Optional[QThread] = None
        self.worker: Optional[ScanWorker] = None

        self._init_models()
        self._init_ui()
        self._init_menu()

    def _init_models(self):
        self.model = CertificateTableModel(self)
        self.proxy_model = CertificateFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setSortRole(Qt.ItemDataRole.UserRole)

    def _init_menu(self):
        menu_bar = self.menuBar()

        # Меню "Вид" с выбором темы (тестовое)
        veiw_menu = menu_bar.addMenu("Вид")
        theme_menu = veiw_menu.addMenu("Тема оформления")

        self.theme_action_group = QActionGroup(self)
        self.theme_action_group.setExclusive(True)

        theme_choices = [
            ("Системная", ThemeMode.SYSTEM),
            ("Светлая", ThemeMode.LIGHT),
            ("Тёмная (ночная)", ThemeMode.DARK),
        ]

        current_mode = self.theme_manager.current_mode

        for label, mode in theme_choices:
            action = QAction(label, self, checkable=True)
            action.setData(mode)
            if mode == current_mode:
                action.setChecked(True)
            action.triggered.connect(lambda checked, m=mode: self.theme_manager.set_mode(m))
            self.theme_action_group.addAction(action)
            theme_menu.addAction(action)

        # Меню "Справка"
        help_menu = menu_bar.addMenu("Справка")
        info_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)
        about_action = QAction(info_icon, "О программе...", self)
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Первый блок. Параметры сканирования
        paths_group = QGroupBox("Параметры сканирования")
        paths_layout = QVBoxLayout(paths_group)

        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Папка"))
        self.input_dir_edit = QLineEdit()
        dir_layout.addWidget(self.input_dir_edit)
        self.btn_browse_dir = QPushButton("Обзор...")
        self.btn_browse_dir.clicked.connect(self._browse_input_dir)
        dir_layout.addWidget(self.btn_browse_dir)
        paths_layout.addLayout(dir_layout)

        csv_layout = QHBoxLayout()
        csv_layout.addWidget(QLabel("CSV-файл:"))
        self.output_csv_edit = QLineEdit(str(Path.cwd() / "certificates_info.csv"))
        csv_layout.addWidget(self.output_csv_edit)
        self.btn_browse_csv = QPushButton("Обзор...")
        self.btn_browse_csv.clicked.connect(self._browse_output_csv)
        csv_layout.addWidget(self.btn_browse_csv)
        paths_layout.addLayout(csv_layout)

        main_layout.addWidget(paths_group)

        # Второй блок. Панель действий
        action_layout = QHBoxLayout()
        self.btn_start = QPushButton("Начать обработку")
        self.btn_start.setFixedHeight(35)
        self.btn_start.clicked.connect(self._start_processing)
        action_layout.addWidget(self.btn_start)

        self.btn_cancel = QPushButton("Отмена")
        self.btn_cancel.setFixedHeight(35)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_processing)
        action_layout.addWidget(self.btn_cancel)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        action_layout.addWidget(self.progress_bar)

        main_layout.addLayout(action_layout)

        #Панель третья. Фильтрация результатов
        filter_group = QGroupBox("Фильтрация и поиск")
        filter_layout = QHBoxLayout(filter_group)

        filter_layout.addWidget(QLabel("Поиск"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("ФИО, организация, должность, отпечаток...")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._on_search_changed)
        filter_layout.addWidget(self.search_edit)

        filter_layout.addWidget(QLabel("Срок действия:"))
        self.status_combo = QComboBox()
        self.status_combo.addItems([
            "Все сертификаты",
            "Действующие",
            "Истекают скоро (до 30 дней)",
            "Истекшие"
        ])
        self.status_combo.currentIndexChanged.connect(self._on_status_changed)
        filter_layout.addWidget(self.status_combo)

        main_layout.addWidget(filter_group)

        # Четвертый блок. Таблица с результатами
        self.table_view = QTableView()
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSortingEnabled(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.table_view)

        # Пятый блок. Статусбар (тестовое)
        self.status_label = QLabel("Готов к работе")
        main_layout.addWidget(self.status_label)

    def _show_about_dialog(self):
        about_text = f"""
        <h3>Анализ сертификатов X.509</h3>
        <p><b>Версия:</b> {APP_VERSION}</p>
        <p>Высокопроизводительная утилита парсинга и анализа цифровых подписей.</p>
        <hr>
        <p>Поддержка тем оформления, для удобства использования</p>
        <p><b>Автор:</b> Степанчук Валерий Викторович</p>
        <p><b>E-mail:</b> valerik.shadowman@gmail.com</p>
        <p><b>GitHub:</b> https://github.com/ValeriCHHH</p>
        """
        QMessageBox.about(self, "О программе", about_text)

    def _browse_input_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "Папка с сертификатами")
        if directory:
            self.input_dir_edit.setText(directory)

    def _browse_output_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить CSV", self.output_csv_edit.text(), "CSV Files (*.csv)"
        )
        if path:
            self.output_csv_edit.setText(path)

    def _start_processing(self):
        source_dir = Path(self.input_dir_edit.text().strip())
        output_csv = Path(self.output_csv_edit.text().strip())

        if not source_dir.is_dir():
            QMessageBox.critical(self, "Ошибка", "Указанная директория/папка не существует!")
            return

        self.model.clear()
        self.progress_bar.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.status_label.setText("Сканирование")

        self.thread = QThread()
        self.worker = ScanWorker(source_dir, output_csv)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.batch_ready.connect(self.model.add_records)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _cancel_processing(self):
        if self.thread and self.thread.isRunning():
            self.thread.requestInterruption()
            self.status_label.setText("Прерывание операции...")
            self.btn_cancel.setEnabled(False)

    def _on_progress(self, current: int, total: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self._update_status_counts()

    def _on_search_changed(self, text: str):
        self.proxy_model.set_search_query(text)
        self._update_status_counts()

    def _on_status_changed(self, index: int):
        self.proxy_model.set_expiration_filter(ExpirationStatus(index))
        self._update_status_counts()

    def _update_status_counts(self):
        shown = self.proxy_model.rowCount()
        total = self.model.rowCount()
        self.status_label.setText(f"Отображенно: {shown} из {total}")

    def _on_finished(self, success: int, errors: int, was_cancelled: bool):
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._update_status_counts()

        if was_cancelled:
            QMessageBox.warning(self, "Прервано", f"Операция отменена. \nУспешно обработано: {success}")
        elif success == 0 and errors == 0:
            QMessageBox.information(self, "Готово", "Подходящих файлов не найдено.")
        else:
            QMessageBox.information(
                self, "Готово", f"Обработка завершена!\nУспешно: {success}\nОшибок: {errors}"
            )

    def _on_error(self, err_msg: str):
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        QMessageBox.critical(self, "Критическая ошибка", err_msg)


def main():
    app = QApplication(sys.argv)

    # Fusion должен гарантировать работу палитры на всех ОС
    app.setStyle("Fusion")

    # Инициализируем и применяем тему до показа окна программы
    theme_manager = ThemeManager(app)
    theme_manager.apply_theme()

    window = MainWindow(theme_manager)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()