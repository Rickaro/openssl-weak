#requires -Version 5.1
<#
.SYNOPSIS
    Аудит TLS-конфигурации HTTPS-сервера через openssl s_client.

.DESCRIPTION
    Проверяет:
      * поддержку версий протокола (TLS 1.3 / 1.2 и устаревшие TLS 1.1 / 1.0 / SSL 3.0);
      * слабые и legacy шифры (NULL, EXPORT, RC4, 3DES, DES, MD5, anon, DSS);
      * forward secrecy (шифры с RSA key exchange без ECDHE/DHE);
      * сведения о сертификате: издатель, срок действия, ключ, подпись, SAN.

    Exit code 1, если найдены FAIL — можно использовать как гейт в CI.

.PARAMETER Target
    host, host:port или URL вида https://host/path.

.PARAMETER OpensslPath
    Путь к openssl.exe. По умолчанию — openssl.exe рядом со скриптом, затем из PATH.

.PARAMETER CipherScan
    None — только версии протокола и сертификат (быстро).
    Weak — перебор известных слабых/legacy шифров TLS 1.2 (по умолчанию).
    Full — перебор всех шифров TLS 1.2 (медленно, минуты).

.PARAMETER OutFile
    Дополнительно сохранить отчёт в текстовый файл.

.EXAMPLE
    .\tls-check.ps1 portal.example.ru

.EXAMPLE
    .\tls-check.ps1 https://portal.example.ru -CipherScan Full -OutFile report.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [string]$OpensslPath,

    [string]$Sni,

    [int]$Port,

    [ValidateSet('None', 'Weak', 'Full')]
    [string]$CipherScan = 'Weak',

    [string]$OutFile,

    [int]$TimeoutSec = 25
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- отчёт ------
$script:Report = New-Object System.Collections.Generic.List[string]
$script:Counts = @{ PASS = 0; WARN = 0; FAIL = 0; INFO = 0 }

function Add-Line {
    param([string]$Status, [string]$Text)

    $prefix = '[{0}] {1}' -f $Status.PadRight(4), $Text
    $script:Report.Add($prefix)

    $color = 'Gray'
    switch ($Status) {
        'PASS' { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'FAIL' { $color = 'Red' }
        'INFO' { $color = 'Cyan' }
    }
    Write-Host $prefix -ForegroundColor $color

    $script:Counts[$Status] = $script:Counts[$Status] + 1
}

function Add-Section {
    param([string]$Title)
    $script:Report.Add('')
    $script:Report.Add("--- $Title ---")
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor White
}

# ------------------------------------------------------------- параметры -----
$connectHost = $Target.Trim()
if ($connectHost -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
    $connectHost = $connectHost -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', ''
}
$connectHost = ($connectHost -split '[/?#]')[0]
if ($connectHost -match '@') { $connectHost = $connectHost.Split('@')[-1] }

$connectPort = 443
if ($connectHost -match '^(?<h>.+):(?<p>\d+)$') {
    $connectHost = $Matches.h
    $connectPort = [int]$Matches.p
}
if ($PSBoundParameters.ContainsKey('Port')) { $connectPort = $Port }

if (-not $Sni) { $Sni = $connectHost }
$connect = '{0}:{1}' -f $connectHost, $connectPort

# ---------------------------------------------------------------- openssl ----
if (-not $OpensslPath) {
    $local = Join-Path $PSScriptRoot 'openssl.exe'
    if (Test-Path -LiteralPath $local) {
        $OpensslPath = (Resolve-Path -LiteralPath $local).Path
    } else {
        $fromPath = Get-Command openssl -ErrorAction SilentlyContinue
        if ($fromPath) { $OpensslPath = $fromPath.Source }
    }
}
if (-not $OpensslPath -or -not (Test-Path -LiteralPath $OpensslPath)) {
    throw 'openssl не найден. Укажите -OpensslPath или положите openssl.exe рядом со скриптом.'
}
$OpensslPath = (Resolve-Path -LiteralPath $OpensslPath).Path

# --------------------------------------------------------------- провайдеры --
# В OpenSSL 3.x RC4/3DES/DES/IDEA/SEED живут в legacy-провайдере. Без него
# перебор слабых шифров молча не находит ничего и даёт ложный PASS.
$script:ProviderArgs = @()
$script:LegacyAvailable = $false

$legacyProbe = ''
try {
    $legacyListArgs = @('ciphers', '-provider', 'default', '-provider', 'legacy', 'ALL:eNULL:aNULL:@SECLEVEL=0')
    $legacyProbe = ((& $OpensslPath @legacyListArgs 2>&1) -join '')
} catch {
    $legacyProbe = ''
}

if ($legacyProbe -match 'DES-CBC3-SHA|RC4-') {
    $script:ProviderArgs = @('-provider', 'default', '-provider', 'legacy')
    $script:LegacyAvailable = $true
}

# Какие протоколы умеет сама сборка openssl (а не сервер).
$sclientHelp = ''
try {
    $sclientHelp = ((& $OpensslPath s_client -help 2>&1) -join "`n")
} catch {
    $sclientHelp = ''
}

function Test-LocalProtocol {
    param([string]$Option)
    if (-not $sclientHelp) { return $true }
    return [bool]($sclientHelp -match ('(?m)^\s*' + [regex]::Escape($Option) + '\b'))
}

# Запуск s_client с гарантированным таймаутом и корректным ExitCode.
# stderr читаем тоже: s_client -brief пишет сводку именно туда.
function Invoke-SClient {
    param([string[]]$Arguments, [int]$Timeout = $TimeoutSec)

    $argLine = (@('s_client') + $script:ProviderArgs + @('-connect', $connect, '-servername', $Sni) + $Arguments) |
        ForEach-Object {
            if ($_ -match '[\s"]') { '"{0}"' -f ($_ -replace '"', '\"') } else { $_ }
        }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $OpensslPath
    $psi.Arguments = ($argLine -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    try {
        $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    } catch { }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    try {
        if (-not $proc.Start()) { throw "не удалось запустить $OpensslPath" }

        # пустой stdin => s_client завершает сессию сразу после handshake
        try { $proc.StandardInput.Close() } catch { }

        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()

        if (-not $proc.WaitForExit($Timeout * 1000)) {
            try { $proc.Kill() } catch { }
            return [pscustomobject]@{ ExitCode = -1; Output = @('timeout'); TimedOut = $true }
        }
        $proc.WaitForExit()

        $stdout = ''
        $stderr = ''
        try { $stdout = $outTask.Result } catch { }
        try { $stderr = $errTask.Result } catch { }

        $lines = @((($stdout + "`n" + $stderr) -split "`r?`n") | Where-Object { $_ -ne '' })

        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            Output   = $lines
            TimedOut = $false
        }
    } finally {
        $proc.Dispose()
    }
}

function Get-HandshakeInfo {
    param($Result)
    $info = [pscustomobject]@{ Protocol = $null; Cipher = $null; Verification = $null }

    if (-not $Result -or $Result.TimedOut) { return $info }
    $text = ($Result.Output -join "`n")

    if ($text -match '(?im)^\s*Protocol\s*version:\s*(\S+)') { $info.Protocol = $Matches[1] }
    elseif ($text -match '(?im)^\s*Protocol\s*:\s*(\S+)') { $info.Protocol = $Matches[1] }

    if ($text -match '(?im)^\s*(?:Ciphersuite|Cipher)\s*:\s*(\S+)') { $info.Cipher = $Matches[1] }

    if ($text -match '(?im)^\s*Verification(?: error)?:\s*(.+)$') { $info.Verification = $Matches[1].Trim() }

    return $info
}

Add-Line 'INFO' ("Цель: {0} (SNI: {1})" -f $connect, $Sni)
$versionOut = ((& $OpensslPath version 2>&1) -join ' ').Trim()
Add-Line 'INFO' ("openssl: {0}" -f $versionOut)
Add-Line 'INFO' ("Путь: {0}" -f $OpensslPath)
if ($script:LegacyAvailable) {
    Add-Line 'INFO' 'legacy provider подключён: RC4/3DES/DES/IDEA/SEED проверяемы'
}

# --------------------------------------------------------------- протоколы ---
Add-Section 'Версии протокола'

$protocols = @(
    @{ Name = 'TLS 1.3'; Arg = '-tls1_3'; Wire = 'TLSv1.3'; Legacy = $false },
    @{ Name = 'TLS 1.2'; Arg = '-tls1_2'; Wire = 'TLSv1.2'; Legacy = $false },
    @{ Name = 'TLS 1.1'; Arg = '-tls1_1'; Wire = 'TLSv1.1'; Legacy = $true },
    @{ Name = 'TLS 1.0'; Arg = '-tls1'; Wire = 'TLSv1'; Legacy = $true },
    @{ Name = 'SSL 3.0'; Arg = '-ssl3'; Wire = 'SSLv3'; Legacy = $true }
)

$supported = @{}
$negotiated = @{}
foreach ($proto in $protocols) {
    if (-not (Test-LocalProtocol -Option $proto.Arg)) {
        $supported[$proto.Name] = $null
        Add-Line 'INFO' ("{0}: локальная сборка openssl не поддерживает этот протокол — проверить нельзя" -f $proto.Name)
        continue
    }

    # открытый список шифров + SECLEVEL=0: клиентская политика не должна
    # маскировать поддержку протокола сервером
    $probeArgs = @('-brief', $proto.Arg, '-cipher', 'ALL:eNULL:aNULL:@SECLEVEL=0')

    $r = Invoke-SClient -Arguments $probeArgs
    $hs = Get-HandshakeInfo -Result $r

    # критерий — установленный handshake, а не ExitCode:
    # при непроверенном сертификате s_client возвращает 1, но протокол работает
    $ok = [bool]($hs.Protocol -and $hs.Protocol.StartsWith($proto.Wire))
    $supported[$proto.Name] = [bool]$ok
    $negotiated[$proto.Name] = $hs

    if ($ok) {
        if ($proto.Legacy) {
            Add-Line 'FAIL' ("{0}: сервер принимает соединение ({1}) — устаревший протокол нужно отключить" -f $proto.Name, $hs.Protocol)
        } else {
            Add-Line 'PASS' ("{0}: поддерживается ({1})" -f $proto.Name, $hs.Protocol)
        }
    } elseif ($proto.Legacy) {
        Add-Line 'PASS' ("{0}: не поддерживается" -f $proto.Name)
    } else {
        Add-Line 'FAIL' ("{0}: не поддерживается" -f $proto.Name)
    }
}

$reachable = (@($supported.Values | Where-Object { $_ -eq $true }).Count -gt 0)
$modernKnown = ($null -ne $supported['TLS 1.3']) -or ($null -ne $supported['TLS 1.2'])

if (-not $reachable) {
    if ($modernKnown) {
        Add-Line 'FAIL' 'Ни одно TLS-соединение не установилось: хост недоступен, порт закрыт или это не TLS. Остальные проверки пропущены.'
    } else {
        Add-Line 'INFO' 'Локальная сборка не поддерживает TLS 1.3/1.2 — проверить протоколы невозможно.'
    }
}

if (-not $script:LegacyAvailable) {
    Add-Line 'WARN' 'legacy provider недоступен: RC4/3DES/DES/IDEA/SEED проверить нельзя — по ним результат не подтверждён'
}

if ($supported['TLS 1.2'] -eq $true -and $supported['TLS 1.3'] -eq $false) {
    Add-Line 'WARN' 'TLS 1.3 не включён — рекомендуется включить (производительность + Forward Secrecy по умолчанию)'
}

$verify = $null
foreach ($name in @('TLS 1.3', 'TLS 1.2')) {
    if ($supported[$name] -and $negotiated[$name].Verification) {
        $verify = $negotiated[$name].Verification
        break
    }
}
if ($verify) {
    if ($verify -match '(?i)^ok') {
        Add-Line 'PASS' ("Цепочка сертификатов проверена клиентом: {0}" -f $verify)
    } else {
        Add-Line 'WARN' ("Проверка цепочки клиентом: {0}" -f $verify)
    }
}

# ------------------------------------------------------------ шифры TLS 1.3 -
if ($reachable) {
    Add-Section 'Шифры TLS 1.3'

    $tls13Suites = @(
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
    )

    $tls13Found = @()
    if ($supported['TLS 1.3']) {
        foreach ($suite in $tls13Suites) {
            $r = Invoke-SClient -Arguments @('-brief', '-tls1_3', '-ciphersuites', $suite)
            $hs = Get-HandshakeInfo -Result $r
            if ($hs.Protocol -eq 'TLSv1.3') { $tls13Found += $suite }
        }
        if ($tls13Found.Count -gt 0) {
            Add-Line 'PASS' ("Поддерживаются AEAD-шифры: {0}" -f ($tls13Found -join ', '))
        } else {
            Add-Line 'WARN' 'TLS 1.3 есть, но ни один из стандартных AEAD-шифров не подтвердился'
        }
    } else {
        Add-Line 'INFO' 'TLS 1.3 не используется — проверка шифров пропущена'
    }
}

# ------------------------------------------------------------ шифры TLS 1.2 -
if ($CipherScan -ne 'None') {
    Add-Section 'Слабые и legacy шифры TLS 1.2'

    if (-not $supported['TLS 1.2']) {
        Add-Line 'INFO' 'TLS 1.2 не подтверждён — перебор шифров пропущен (иначе возможен ложный PASS)'
    } else {
        $cipherText = ''
        try {
            $cipherArgs = @('ciphers') + $script:ProviderArgs + @('ALL:eNULL:aNULL:@SECLEVEL=0')
            $cipherText = ((& $OpensslPath @cipherArgs 2>&1) -join '').Trim()
        } catch {
            $cipherText = ''
        }

        if (-not $cipherText) {
            Add-Line 'INFO' 'Не удалось получить список шифров локальной сборки openssl'
        } else {
            $allCiphers = @($cipherText -split ':' | Where-Object { $_ })

            $weakPattern = '(?i)NULL|EXPORT|RC4|3DES|(^|[_-])DES([_-]|$)|MD5|IDEA|SEED|anon|ADH|AECDH|DSS'
            if ($CipherScan -eq 'Weak') {
                $candidates = @($allCiphers | Where-Object { $_ -match $weakPattern })
            } else {
                $candidates = $allCiphers
            }

            Add-Line 'INFO' ("Проверяется шифров: {0} из {1}" -f $candidates.Count, $allCiphers.Count)

            $accepted = @()
            $i = 0
            foreach ($cipher in $candidates) {
                $i++
                Write-Progress -Activity 'Перебор шифров TLS 1.2' -Status $cipher `
                    -PercentComplete (100 * $i / [Math]::Max(1, $candidates.Count))

                $r = Invoke-SClient -Arguments @('-brief', '-tls1_2', '-cipher', ($cipher + ':@SECLEVEL=0'))
                $hs = Get-HandshakeInfo -Result $r
                if ($hs.Protocol -eq 'TLSv1.2') { $accepted += $cipher }
            }
            Write-Progress -Activity 'Перебор шифров TLS 1.2' -Completed

            $weakAccepted = @($accepted | Where-Object { $_ -match $weakPattern })
            $noPfs = @($accepted | Where-Object { $_ -notmatch '^(TLS_)?(ECDHE|DHE)' })

            if ($CipherScan -eq 'Weak') {
                if ($weakAccepted.Count -eq 0) {
                    Add-Line 'PASS' 'Слабые/legacy шифры TLS 1.2 не принимаются'
                } else {
                    foreach ($c in $weakAccepted) {
                        Add-Line 'FAIL' ("принимается слабый шифр: {0}" -f $c)
                    }
                }
                if ($noPfs.Count -gt 0) {
                    foreach ($c in $noPfs) {
                        Add-Line 'WARN' ("шифр без forward secrecy (RSA key exchange): {0}" -f $c)
                    }
                }
            } else {
                Add-Line 'INFO' ("Принимается шифров TLS 1.2: {0}" -f $accepted.Count)
                foreach ($c in $accepted) {
                    if ($c -match $weakPattern) {
                        Add-Line 'FAIL' ("принимается слабый шифр: {0}" -f $c)
                    } elseif ($c -notmatch '^(TLS_)?(ECDHE|DHE)') {
                        Add-Line 'WARN' ("без forward secrecy: {0}" -f $c)
                    } else {
                        Add-Line 'PASS' ("{0}" -f $c)
                    }
                }
                if ($accepted.Count -eq 0) {
                    Add-Line 'FAIL' 'Ни один шифр TLS 1.2 не подтвердился'
                }
            }
        }
    }
}

# ------------------------------------------------------------- сертификат ----
if ($reachable) {
    Add-Section 'Сертификат'

    # для серверов без TLS 1.2/1.3 сертификат читаем на максимально доступном протоколе
    $certProtoArgs = @()
    if ($supported['TLS 1.2'] -ne $true) {
        if ($supported['TLS 1.1'] -eq $true) { $certProtoArgs = @('-tls1_1') }
        elseif ($supported['TLS 1.0'] -eq $true) { $certProtoArgs = @('-tls1') }
    }
    $certRun = Invoke-SClient -Arguments (@('-showcerts', '-cipher', 'ALL:eNULL:aNULL:@SECLEVEL=0') + $certProtoArgs)
    $certLines = @($certRun.Output)

    $beginIdx = -1
    $endIdx = -1
    for ($i = 0; $i -lt $certLines.Count; $i++) {
        if ($certLines[$i] -match '^-----BEGIN CERTIFICATE-----') { $beginIdx = $i; break }
    }
    if ($beginIdx -ge 0) {
        for ($j = $beginIdx; $j -lt $certLines.Count; $j++) {
            if ($certLines[$j] -match '^-----END CERTIFICATE-----') { $endIdx = $j; break }
        }
    }

    if ($beginIdx -lt 0 -or $endIdx -lt 0) {
        Add-Line 'FAIL' 'Не удалось получить сертификат сервера'
    } else {
        $pem = ($certLines[$beginIdx..$endIdx]) -join "`n"
        $tmpCert = [System.IO.Path]::GetTempFileName()
        try {
            Set-Content -LiteralPath $tmpCert -Value $pem -Encoding Ascii
            $certInfo = ((& $OpensslPath x509 -in $tmpCert -noout -text 2>&1) -join "`n")
            $certRows = @($certInfo -split "`r?`n")

            if ($certInfo -match '(?m)^\s*Issuer:\s*(.+)$') {
                Add-Line 'INFO' ("Издатель: {0}" -f $Matches[1].Trim())
            }
            if ($certInfo -match '(?m)^\s*Subject:\s*(.+)$') {
                Add-Line 'INFO' ("Субъект: {0}" -f $Matches[1].Trim())
            }
            if ($certInfo -match '(?m)^\s*Not Before:\s*(.+)$') {
                Add-Line 'INFO' ("Действителен с: {0}" -f $Matches[1].Trim())
            }

            if ($certInfo -match '(?m)^\s*Not After\s*:\s*(.+)$') {
                $rawDate = $Matches[1].Trim()
                $normalizedDate = ($rawDate -replace '\s+', ' ').Trim()

                $notAfterUtc = $null
                foreach ($format in @("MMM d HH:mm:ss yyyy 'GMT'", "MMM d HH:mm:ss yyyy")) {
                    try {
                        $parsed = [datetime]::ParseExact($normalizedDate, $format, [Globalization.CultureInfo]::InvariantCulture)
                        $notAfterUtc = [datetime]::SpecifyKind($parsed, 'Utc')
                        break
                    } catch { }
                }
                if (-not $notAfterUtc) {
                    try {
                        $parsed = [datetime]::Parse($normalizedDate, [Globalization.CultureInfo]::InvariantCulture)
                        $notAfterUtc = [datetime]::SpecifyKind($parsed, 'Utc')
                    } catch { $notAfterUtc = $null }
                }

                if ($notAfterUtc) {
                    $days = [int][Math]::Floor(($notAfterUtc - [datetime]::UtcNow).TotalDays)
                    if ($days -lt 0) {
                        Add-Line 'FAIL' ("Сертификат просрочен: {0} ({1} дн.)" -f $rawDate, $days)
                    } elseif ($days -lt 30) {
                        Add-Line 'WARN' ("Сертификат истекает через {0} дн.: {1}" -f $days, $rawDate)
                    } else {
                        Add-Line 'PASS' ("Срок действия ок: осталось {0} дн. (до {1})" -f $days, $rawDate)
                    }
                } else {
                    Add-Line 'INFO' ("Действителен до: {0}" -f $rawDate)
                }
            }

            $keyAlg = $null
            if ($certInfo -match '(?m)^\s*Public Key Algorithm:\s*(.+)$') { $keyAlg = $Matches[1].Trim() }
            $bits = $null
            if ($certInfo -match '(?m)^\s*Public-Key:\s*\((\d+) bit\)') { $bits = [int]$Matches[1] }

            if ($keyAlg) {
                Add-Line 'INFO' ("Алгоритм ключа: {0}" -f $keyAlg)
            }

            if ($keyAlg -match '(?i)rsa') {
                if ($bits -and $bits -lt 2048) {
                    Add-Line 'FAIL' ("Ключ RSA короче 2048 бит: {0} бит" -f $bits)
                } elseif ($bits) {
                    Add-Line 'PASS' ("Длина ключа RSA: {0} бит" -f $bits)
                }
            } elseif ($keyAlg -match '(?i)ec|ed25519|ed448') {
                $curve = $null
                if ($certInfo -match '(?m)^\s*NIST CURVE:\s*(.+)$') { $curve = $Matches[1].Trim() }
                elseif ($certInfo -match '(?m)^\s*ASN1 OID:\s*(.+)$') { $curve = $Matches[1].Trim() }

                if ($curve) {
                    Add-Line 'PASS' ("Ключ: {0} ({1})" -f $keyAlg, $curve)
                } else {
                    Add-Line 'PASS' ("Ключ: {0}" -f $keyAlg)
                }
            } elseif ($bits) {
                Add-Line 'INFO' ("Длина ключа: {0} бит" -f $bits)
            }

            if ($certInfo -match '(?m)^\s*Signature Algorithm:\s*(\S+)') {
                $sigAlg = $Matches[1]
                if ($sigAlg -match '(?i)md5|sha1\b') {
                    Add-Line 'FAIL' ("Подпись сертификата на устаревшем алгоритме: {0}" -f $sigAlg)
                } else {
                    Add-Line 'PASS' ("Алгоритм подписи: {0}" -f $sigAlg)
                }
            }

            # SAN парсим построчно: блок SAN идёт без пустой строки перед следующим extension
            $sanValues = New-Object System.Collections.Generic.List[string]
            $inSan = $false
            foreach ($row in $certRows) {
                $t = $row.Trim()
                if ($t -match '^X509v3 Subject Alternative Name:') { $inSan = $true; continue }
                if ($inSan) {
                    if ($t -eq '') { break }
                    if ($t -match '^(DNS|IP Address|URI|email|othername|DirName|Registered ID):') {
                        foreach ($value in ($t -split ',\s*')) { $sanValues.Add($value.Trim()) }
                    } else {
                        break
                    }
                }
            }

            $dnsNames = @($sanValues | Where-Object { $_ -match '(?i)^DNS:' } | ForEach-Object { ($_ -replace '(?i)^DNS:', '') })
            if ($dnsNames.Count -gt 0) {
                Add-Line 'INFO' ("SAN (DNS): {0}" -f (($dnsNames | Select-Object -First 10) -join ', '))

                $matched = $false
                foreach ($dns in $dnsNames) {
                    if ($Sni -like $dns) { $matched = $true; break }
                }
                if (-not $matched) {
                    Add-Line 'WARN' ("Ни одно имя в SAN не покрывает '{0}' — браузеры такое соединение отклонят" -f $Sni)
                }
            }

            $keyUsageText = ''
            if ($certInfo -match '(?ms)X509v3 Key Usage[^\n]*\n\s*(?<ku>[^\n]+)') {
                $keyUsageText = $Matches['ku'].Trim()
                Add-Line 'INFO' ("Key Usage: {0}" -f $keyUsageText)
            }
            if ($certInfo -match '(?ms)X509v3 Extended Key Usage:\s*\n?\s*(?<eku>[^\n]+)') {
                $eku = $Matches['eku'].Trim()
                if ($eku -notmatch '(?i)server\s*auth|web server authentication') {
                    Add-Line 'FAIL' ("В EKU нет serverAuth: {0}" -f $eku)
                } else {
                    Add-Line 'PASS' ("EKU: {0}" -f $eku)
                }
            }
        } finally {
            Remove-Item -LiteralPath $tmpCert -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------- итог -------
Add-Section 'Итог'
Add-Line 'INFO' ("PASS: {0}   WARN: {1}   FAIL: {2}" -f $script:Counts['PASS'], $script:Counts['WARN'], $script:Counts['FAIL'])

if ($OutFile) {
    $script:Report -join [Environment]::NewLine | Set-Content -LiteralPath $OutFile -Encoding UTF8
    Write-Host ''
    Write-Host ("Отчёт сохранён: {0}" -f (Resolve-Path -LiteralPath $OutFile).Path) -ForegroundColor Cyan
}

if ($script:Counts['FAIL'] -gt 0) { exit 1 }
exit 0
