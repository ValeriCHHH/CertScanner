#!/usr/bin/evn python3

"""
CLI-утилита для рекурсивного поиска файлов сертификатов X.509
и параллельного экспорта метаданных в CSV.
"""

from __future__ import annotations

import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ObjectIdentifier

SUPPORTED_EXTENSIONS = {".cer", ".crt", ".pem", ".der"}
FIELDNAMES = [
    "Ф.И.О.",
    "Должность",
    "Организация",
    "Действителен до",
    "Отпечаток SHA1",
    "Отпечаток SHA256",
]


@dataclass(slots=True, frozen=True)
class CertRecord:
    fio: str
    position: str
    organization: str
    not_after: datetime
    thumbprint_sha1: str
    thumbprint_sha256: str

    def to_csv_dict(self) -> dict[str, str]:
        return {
            "Ф.И.О.": self.fio,
            "Должность": self.position,
            "Организация": self.organization,
            "Действителен до": self.not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "Отпечаток SHA1": self.thumbprint_sha1,
            "Отпечаток SHA256": self.thumbprint_sha256,
        }


def get_subject_attr(cert: x509.Certificate, oid: ObjectIdentifier) -> Optional[str]:
    attrs = cert.subject.get_attributes_for_oid(oid)
    if attrs and attrs[0].value is not None:
        return str(attrs[0].value)
    return None


def extract_cert_info(cert_path: Path) -> CertRecord:
    cert_data = cert_path.read_bytes()

    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_data)

    sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()

    cn = get_subject_attr(cert, NameOID.COMMON_NAME)
    sn = get_subject_attr(cert, NameOID.SURNAME)
    gn = get_subject_attr(cert, NameOID.GIVEN_NAME)
    org = get_subject_attr(cert, NameOID.ORGANIZATION_NAME) or "Не указано"
    title = get_subject_attr(cert, NameOID.TITLE) or "Не указано"

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
    )


def find_certificate_files(source_dir: Path, recursive: bool = True) -> Iterator[Path]:
    """Генератор поиска подходящих файлов (попытка минимизировать потребление памяти)."""
    pattern = "**/*" if recursive else "*"
    for p in source_dir.glob(pattern):
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield p


def parse_worker(cert_path: Path) -> tuple[Optional[CertRecord], Optional[str]]:
    """Вспомогательная функция для пула потоков."""
    try:
        return extract_cert_info(cert_path), None
    except Exception as exc:
        return None, f"Ошибка в '{cert_path}': {exc}"


def process_certificates(
        source_dir: Path,
        output_csv: Path,
        max_workers: Optional[int] = None,
        recursive: bool = True,
        quiet: bool = False,
) -> int:
    if not source_dir.is_dir():
        print(f"Ошибка: путь '{source_dir}' не найден или не является директорией (папкой).", file=sys.stderr)
        return 1

    if not quiet:
        print(f"Поиск сертификатов в '{source_dir}' ... ")

    cert_files = list(find_certificate_files(source_dir, recursive=recursive))
    total_files = len(cert_files)

    if not quiet:
        print(f"Найдено файлов для обработки: {total_files}")

    if total_files == 0:
        return 0

    output_csv.resolve().parent.mkdir(parents=True, exist_ok=True)

    succes_count = 0
    error_count = 0

    with open(output_csv, mode="w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES, delimiter=";")
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Отправка задач в пул
            futures = {executor.submit(parse_worker, path): path for path in cert_files}

            for idx, future in enumerate(as_completed(futures), start=1):
                record, error = future.result()

                if record:
                    writer.writerow(record.to_csv_dict())
                    succes_count += 1
                else:
                    error_count += 1
                    if not quiet:
                        # Очищаем страоку перед выводом ошибки, чтобы не ломать прогресс
                        sys.stderr.write(f"\r\033[K{error}\n")

                    if not quiet and sys.stdout.isatty():
                        percent = (idx / total_files) * 100
                        sys.stdout.write(f"\rОбработка: [{idx}/{total_files}] {percent:.1f}%")
                        sys.stdout.flush()

        if not quiet:
            if sys.stdout.isatty():
                sys.stdout.write("\r\033[K") # Очищаем строку прогресса
            print(f"Готово! Успешно: {succes_count}, ошибок: {error_count}")
            print(f"Файл сохранён: {output_csv.resolve()}")

        return 0 if error_count == 0 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cert2csv",
        description="Быстрый поиск сертификатов X.509 и экспорт данных в CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "dir",
        type=Path,
        help="Директория для поиска файлов сертификатов",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("certificates_info.csv"),
        help="Путь к результирующему CSV-файлу",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Количество потоков обработки (по умолчанию: число ядер CPU)"
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Отключить рекурсивный поиск в поддиректориях",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Тихий режим (без вывода в консоль, кроме критических ошибок)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    exit_code = process_certificates(
        source_dir=args.dir,
        output_csv=args.output,
        max_workers=args.workers,
        recursive=not args.no_recursive,
        quiet=args.quiet,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()