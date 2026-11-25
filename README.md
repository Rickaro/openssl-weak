# openssl-weak

Сборка статического `openssl.exe` под Windows x86_64 через GitHub Actions + скрипт аудита TLS.

Задача репозитория: получить **свой** свежий `openssl.exe` без DLL и зависимостей,
чтобы проверять сайты на соответствие требованиям безопасности (версии TLS,
слабые шифры, forward secrecy, сертификат).

## Что внутри

| Путь | Назначение |
| --- | --- |
| `.github/workflows/build-openssl-windows.yml` | сборка openssl под Windows (mingw64, статически) и публикация артефакта |
| `.github/workflows/tls-audit.yml` | опциональный аудит публичного сайта через `testssl.sh` (без сборки) |
| `scripts/tls-check.ps1` | аудит TLS конкретного хоста через `openssl s_client` |

## Сборка openssl

1. Вкладка **Actions** → workflow **Build OpenSSL for Windows (static)** → **Run workflow**.
2. Версия по умолчанию — `3.5.9` (LTS). Можно указать другую, например `4.0.3`.
3. Через ~15 минут скачать артефакт `openssl-<версия>-win64-static`.

Что делает workflow:

* качает исходник с GitHub Releases;
* **сверяет SHA256** с официальным `.sha256` рядом с релизом (несовпадение → сборка падает);
* собирает `mingw64 no-shared no-tests -static` — статические библиотеки, без `libssl-3-x64.dll`/`libcrypto-3-x64.dll`;
* проверяет `ldd`: если что-то всё же осталось динамическим, кладёт нужные DLL рядом;
* делает smoke-тест `openssl.exe version -a` и печатает содержимое артефакта.

Артефакт содержит `openssl.exe` (+ `openssl.cnf`, + DLL при необходимости).
Скачанный zip распаковывается в любую папку — установка не требуется.

Проверка после распаковки:

```powershell
.\openssl.exe version -a
.\openssl.exe ciphers -provider default -provider legacy -s 'ALL:eNULL' | Select-Object -First 1
```

Вторая команда должна вернуть непустой список шифров: **legacy-провайдер
(RC4/3DES/DES/IDEA/SEED) обязателен** для полноценной проверки слабых шифров.
В статической сборке он встроен в бинарник.

## Аудит TLS: scripts/tls-check.ps1

Скрипт работает с любым `openssl` (по умолчанию ищет `openssl.exe` рядом с собой,
затем в `PATH`).

```powershell
# базовый прогон
.\scripts\tls-check.ps1 portal.example.ru

# с отчётом в файл
.\scripts\tls-check.ps1 https://portal.example.ru/login -OutFile report.txt

# полный перебор всех шифров TLS 1.2 (медленно)
.\scripts\tls-check.ps1 portal.example.ru -CipherScan Full

# явно указанный бинарник и нестандартный порт
.\scripts\tls-check.ps1 portal.example.ru -Port 8443 -OpensslPath .\openssl.exe
```

Что проверяется:

* **Версии протокола**: TLS 1.3 / 1.2 (должны быть), TLS 1.1 / 1.0 / SSL 3.0 (должны быть выключены).
* **Шифры TLS 1.3**: какие AEAD-наборы принимаются.
* **Слабые и legacy шифры TLS 1.2**: NULL, EXPORT, RC4, 3DES, DES, MD5, anon, DSS —
  с включённым legacy-провайдером; отдельно помечаются шифры **без forward secrecy**
  (RSA key exchange).
* **Сертификат**: издатель/субъект, срок действия (просрочен / истекает < 30 дней),
  длина ключа (RSA < 2048 → FAIL), алгоритм подписи (MD5/SHA1 → FAIL),
  покрытие имени в SAN, EKU `serverAuth`.

Exit code: `0` — FAIL нет, `1` — есть FAIL (удобно для CI-гейта).

### Честные ограничения

* Скрипт смотрит на **фактический handshake**, а не на конфиг сервера: если
  соединение не установилось, будет FAIL «не поддерживается», а не «не проверил».
* Если локальная сборка openssl не умеет протокол (например `-ssl3` выпилен),
  это печатается как INFO, а не как PASS — ложного «всё хорошо» не будет.
* Если legacy-провайдер недоступен, печатается WARN: RC4/3DES/DES **не проверены**.
  Это не PASS. Доступность провайдера определяется по факту его загрузки
  (`openssl list -providers`), а не по наличию конкретного шифра в списке.
* OpenSSL 3.x может не показывать часть слабых наборов в `ciphers` (зависит от
  security level и политики libssl). Если проверять нечего, печатается WARN
  «нечего проверять», а не «шифры не принимаются».
* Полноценная проверка цепочки доверия требует CA-бандла, которого у автономного
  `openssl.exe` нет. Скрипт выводит результат собственной проверки openssl
  (`Verification: ...`) как WARN, но вердикт по цепочке — не его зона;
  для этого используйте `testssl.sh` или браузерный/OCSP-инструментарий.
* Скрипт не проверяет HTTP-уровень (HSTS, редиректы, заголовки) — только TLS.

## Аудит через testssl.sh (опционально)

Workflow **TLS audit (testssl.sh)** запускается вручную: указываете `target`
(host или URL), получаете `testssl-report.html` и `.json` артефактом.
Ничего собирать не нужно, скрипт гоняется на `ubuntu-latest` как есть.

## Важное про hosted-раннеры

GitHub-hosted раннеры выходят в интернет и **не видят** внутренние адреса
корпоративной сети. Для проверки внутренних стендов нужен self-hosted runner
внутри сети; для публичных сайтов hosted подходит.

## Обновление версии openssl

Версия задаётся при ручном запуске (`version`). Чтобы зафиксировать новую
по умолчанию — поменяйте `default` и fallback-значение в
`.github/workflows/build-openssl-windows.yml`.

## Лицензия

Собирается upstream-код OpenSSL (Apache-2.0); обвязка репозитория — внутренняя.
