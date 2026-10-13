# PRD: DoHSwitch — Auto Change DNS Provider on Chrome (Secure DNS) by Network

| Field | Nilai |
|---|---|
| Versi dokumen | 0.2 |
| Tanggal | 2026-10-13 |
| Pemilik | Ahmad Rayhan |
| Status | Draft, implementasi v0.1 sudah ada di repo (lihat bagian 10) |
| Stack | Windows PowerShell 5.1 bawaan Windows, tanpa modul/library eksternal |
| Target OS | Windows 11 Home 10.0.26200 (PowerShell 5.1.26100) |
| Target browser | Google Chrome 155.0.8059.40 |

---

## 1. Ringkasan

Script PowerShell yang mengatur **Secure DNS** di Google Chrome secara otomatis berdasarkan jaringan tempat laptop berada:

| Jaringan | Setting Chrome `chrome://settings/security` | Policy yang ditulis |
|---|---|---|
| Kantor | Secure DNS: **With your current service provider / OS default (when available)** | `DnsOverHttpsMode = automatic`, `DnsOverHttpsTemplates` dihapus |
| Di luar kantor | Secure DNS: **With Google (Public DNS)** | `DnsOverHttpsMode = secure`, `DnsOverHttpsTemplates = https://dns.google/dns-query{?dns}` |

Trigger utama: **saat logon/startup Windows** lewat Task Scheduler. Trigger tambahan (opsional): saat profil jaringan berubah (pindah WiFi/kabel tanpa restart).

Alasan: di kantor DNS internal (nama host internal, split DNS) harus lewat resolver kantor. Di luar kantor, DNS ISP tidak dipercaya, jadi pakai Google DoH.

---

## 2. Tujuan dan Non-Tujuan

### Tujuan

1. Deteksi "jaringan kantor" dengan aturan yang bisa dikonfigurasi (DNS server, DNS suffix, gateway, SSID, domain-joined, nama profil jaringan).
2. Tulis policy Chrome yang sesuai ke registry tanpa restart Chrome. Butuh proses elevated (lihat 4 dan 5.4), tetapi tanpa prompt UAC saat dijalankan dari task logon.
3. Idempoten: jika policy sudah benar, tidak menulis ulang.
4. Jalan otomatis saat logon. Bisa juga dipicu manual.
5. Bisa di-rollback (`-Reset`) agar Chrome kembali dikontrol user.
6. Punya `-Status` untuk melihat jaringan terdeteksi dan policy aktif.

### Non-Tujuan

- Tidak mengubah DNS level OS Windows.
- Tidak ada pemilihan provider berdasarkan latency (dihapus dari PRD v0.1, tidak sesuai tujuan).
- Tidak ada GUI, tidak ada Chrome extension, tidak ada modul dari PowerShell Gallery.
- Tidak mendukung Firefox. Edge/Brave di luar v1.

---

## 3. Use Case

| ID | Skenario | Hasil |
|---|---|---|
| UC-1 | Nyalakan laptop di kantor, login Windows | 30 detik setelah logon, Chrome memakai "OS default" |
| UC-2 | Nyalakan laptop di rumah/cafe, login Windows | 30 detik setelah logon, Chrome memakai Google Public DNS (DoH) |
| UC-3 | Cek kondisi sekarang | `.\DoHSwitch.ps1 -Status` |
| UC-4 | Paksa mode tertentu untuk uji | `.\DoHSwitch.ps1 -Apply -Force Outside` atau `-Force Office` |
| UC-5 | Lihat apa yang akan terjadi tanpa menulis | `.\DoHSwitch.ps1 -Apply -DryRun` |
| UC-6 | Lepas kontrol policy | `.\DoHSwitch.ps1 -Reset` |
| UC-7 | Pasang / cabut trigger startup | `.\DoHSwitch.ps1 -InstallTask` dan `-UninstallTask` |
| UC-8 | (Opsional) ganti jaringan tanpa restart | `-InstallTask -OnNetworkChange` menambah task event Network Profile |

---

## 4. Stack dan Constraint

| Constraint | Detail |
|---|---|
| Runtime | Windows PowerShell 5.1. Harus tetap jalan di PowerShell 7 |
| Cmdlet | Hanya bawaan: `Get-ItemProperty`, `New-ItemProperty`, `Remove-ItemProperty`, `Get-CimInstance`, `Get-NetAdapter`, `Get-DnsClient`, `Get-DnsClientServerAddress`, `Get-NetRoute`, `Get-NetConnectionProfile`, `Register-ScheduledTask`, `ConvertFrom-Json`, `netsh.exe`, `schtasks.exe` |
| Test | Pester 3.4.0 yang sudah ada di `C:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0` (bawaan Windows, tanpa install) |
| Hak akses | **Semua penulisan butuh PowerShell elevated (Run as Administrator).** Terverifikasi di mesin ini: `HKCU\SOFTWARE\Policies` hanya `ReadKey` untuk user, `FullControl` untuk `BUILTIN\Administrators`. Scope `User` = `HKCU` (default), `Machine` = `HKLM`. `-Status` dan `-DryRun` tidak butuh admin. Task logon dibuat dengan `RunLevel Highest` sehingga jalan elevated tanpa prompt UAC (user ada di grup Administrators) |
| Execution policy | Task memanggil `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...` |
| Encoding | Config/log UTF-8 |

---

## 5. Riset Teknis

### 5.1 Policy Chrome

| Policy | Tipe | Nilai |
|---|---|---|
| `DnsOverHttpsMode` | `REG_SZ` | `off` / `automatic` / `secure` |
| `DnsOverHttpsTemplates` | `REG_SZ` | URI template RFC 8484, dipisah spasi jika lebih dari satu |

Path: `HKCU:\SOFTWARE\Policies\Google\Chrome` (user) atau `HKLM:\SOFTWARE\Policies\Google\Chrome` (mesin). HKLM menang jika keduanya ada.

Pemetaan ke UI Chrome:

- `automatic` tanpa templates = "With your current service provider" (Chrome pakai DoH hanya jika resolver OS dikenal mendukung DoH, selain itu DNS biasa). Ini yang dimaksud "OS default (when available)".
- `secure` + templates Google = "With Google (Public DNS)". Tidak fallback ke DNS biasa.

Chrome di Windows memantau perubahan registry policy dan reload otomatis. Tidak perlu restart Chrome. Verifikasi di `chrome://policy`.

### 5.2 Deteksi jaringan kantor

Fakta yang bisa diambil tanpa library:

| Sinyal | Sumber | Catatan |
|---|---|---|
| DNS server adapter aktif | `Get-DnsClientServerAddress` (filter adapter `Status -eq Up`) | Sinyal paling andal untuk kantor dengan DNS internal |
| DNS suffix | `Get-DnsClient` `ConnectionSpecificSuffix` | Dari DHCP kantor |
| Gateway default | `Get-NetRoute -DestinationPrefix 0.0.0.0/0` | Bisa bentrok dengan rumah (192.168.1.1 umum) |
| SSID WiFi | `netsh wlan show interfaces` | Hanya jika via WiFi |
| Domain-joined | `Win32_ComputerSystem.PartOfDomain` | Laptop ini `WORKGROUP`, tidak berlaku |
| Nama profil jaringan | `Get-NetConnectionProfile` | Windows beri nama "Network 82" dsb, kurang stabil |

Aturan: **kantor jika salah satu rule di `config.json` cocok** (any-of). Tidak ada rule cocok = di luar kantor.

Fakta jaringan saat PRD ini dibuat (2026-10-13, via Ethernet):

| Sinyal | Nilai |
|---|---|
| DNS servers | `192.168.20.3`, `113.212.113.212`, `8.8.8.8` |
| DNS suffix | `lan` |
| Gateway | `192.168.1.1` |
| Profil | `Network 82`, kategori Public |
| Domain | `WORKGROUP` (tidak domain-joined) |

`config.json` saat ini memakai `192.168.20.3` dan suffix `lan` sebagai rule kantor. **Harus dikonfirmasi** apakah jaringan ini memang kantor (lihat OQ-1).

### 5.3 Opsi yang ditolak

| Opsi | Alasan |
|---|---|
| Edit `Local State` Chrome | Harus tutup Chrome, ditimpa ulang, rawan korupsi |
| DoH level OS (`Set-DnsClientDohServerAddress`) | Di luar scope, butuh admin, kena semua aplikasi |
| Ping ke host internal kantor sebagai deteksi | Butuh nama host internal; bisa ditambah nanti sebagai rule opsional |

### 5.4 Temuan saat implementasi

- `HKCU:\SOFTWARE\Policies` dilindungi ACL: user biasa hanya `ReadKey`, owner `NT AUTHORITY\SYSTEM`. `New-Item` tanpa elevasi gagal dengan "Access to the registry key ... is denied". Asumsi "tanpa admin" di PRD v0.1 dibatalkan. Script sekarang menolak dengan exit code `4` jika tidak elevated.
- Extension Claude in Chrome tidak bisa membuka `chrome://policy`, jadi verifikasi Chrome membaca policy (T5) dilakukan manual.

---

## 6. Functional Requirements

| ID | Prio | Requirement | Status |
|---|---|---|---|
| FR-1 | P0 | `-Apply` mendeteksi jaringan, memilih profil `office`/`outside`, menulis policy | Done |
| FR-2 | P0 | Profil `office`: mode `automatic`, value `DnsOverHttpsTemplates` dihapus | Done |
| FR-3 | P0 | Profil `outside`: mode `secure`, templates Google | Done |
| FR-4 | P0 | Rule deteksi dari `config.json`: `dnsServers`, `dnsSuffixes`, `gateways`, `ssids`, `profileNames`, `domainJoined` | Done |
| FR-5 | P0 | Idempoten: tidak menulis jika policy sudah sama | Done |
| FR-6 | P0 | `-Status` menampilkan fakta jaringan, hasil deteksi, policy HKCU dan HKLM, state terakhir | Done |
| FR-7 | P0 | `-Reset` menghapus kedua value dan key jika kosong | Done |
| FR-8 | P0 | Log ke `logs\dohswitch.log` dengan rotasi 1 MB | Done |
| FR-9 | P0 | `-InstallTask` membuat task `DoHSwitch-AtLogon` (trigger logon, delay 30 detik) sebagai user saat ini, `RunLevel Highest` | Done |
| FR-9b | P0 | Guard elevasi: `-Apply`, `-Reset`, `-InstallTask`, `-UninstallTask` tanpa admin keluar dengan exit code `4` dan pesan jelas | Done |
| FR-10 | P0 | `-UninstallTask` menghapus task | Done |
| FR-11 | P1 | `-Force Office|Outside` melewati deteksi | Done |
| FR-12 | P1 | `-DryRun` menampilkan aksi tanpa menulis | Done |
| FR-13 | P1 | Peringatan jika scope `User` tapi `HKLM` sudah punya policy DoH | Done |
| FR-14 | P1 | `-OnNetworkChange` menambah task `DoHSwitch-NetworkChange` (Event ID 10000 `Microsoft-Windows-NetworkProfile/Operational`) | Done |
| FR-15 | P1 | `state.json` menyimpan keputusan terakhir | Done |
| FR-15b | P0 | Repo publik: `config.example.json` dengan `office.match` kosong sebagai template; `config.json`, `state.json`, `logs/` di `.gitignore` karena berisi identitas jaringan user | Done |
| FR-15c | P0 | Guard: `-Apply` tanpa `-Force` keluar exit `1` jika `office.match` kosong (semua jaringan akan jadi outside = Google DoH di kantor) | Done |
| FR-15d | P1 | Semua pesan log/error dalam bahasa Inggris, README Inggris, PRD tetap Indonesia | Done |
| FR-16 | P2 | Rule deteksi tambahan: resolve nama host internal | Backlog |
| FR-17 | P2 | Dukungan Edge/Brave | Backlog |

---

## 7. Desain Script

Satu file `DoHSwitch.ps1`, fungsi di dalamnya, guard `if ($MyInvocation.InvocationName -ne '.')` agar Pester bisa dot-source tanpa menjalankan main.

| Fungsi | Tanggung jawab |
|---|---|
| `Get-Config` | Baca `config.json`, isi default jika field hilang |
| `Get-NetworkFacts` | Kumpulkan DNS server, suffix, gateway, SSID, profil, domain |
| `Test-OfficeNetwork` | Cocokkan fakta dengan rule, kembalikan `IsOffice` dan alasan |
| `Get-DesiredPolicy` | Pilih mode/templates dari profil |
| `Get-DoHPolicy` / `Set-DoHPolicy` / `Remove-DoHPolicy` | Registry |
| `Test-PolicyMatches` | Bandingkan policy aktif vs target |
| `Install-DoHTask` / `Uninstall-DoHTask` | Task Scheduler |
| `Write-Log` | Log file + rotasi |
| `Invoke-Main` | Orkestrasi, exit code |

Alur `-Apply`:

1. Baca config, tentukan scope.
2. Peringatan konflik HKLM.
3. Ambil fakta jaringan, jalankan deteksi (atau pakai `-Force`).
4. Hitung policy target. Baca policy aktif.
5. Sama = log "no change". Beda = tulis (kecuali `-DryRun`), baca ulang, verifikasi.
6. Simpan `state.json`, tulis log.

Exit code: `0` sukses, `1` config error, `3` verifikasi registry gagal, `4` butuh elevasi.

---

## 8. Konfigurasi (`config.json`)

```json
{
  "scope": "User",
  "office": {
    "mode": "automatic",
    "templates": "",
    "match": {
      "domainJoined": false,
      "dnsServers": ["192.168.20.3"],
      "dnsSuffixes": ["lan"],
      "gateways": [],
      "ssids": [],
      "profileNames": []
    }
  },
  "outside": {
    "mode": "secure",
    "templates": "https://dns.google/dns-query{?dns}"
  },
  "logMaxBytes": 1048576
}
```

---

## 9. Test Plan

### 9.1 Unit test (Pester 3.4, `tests\DoHSwitch.Tests.ps1`)

| Test | Verifikasi |
|---|---|
| Deteksi: DNS server cocok | `IsOffice = $true`, alasan berisi `dnsServer` |
| Deteksi: suffix cocok (case-insensitive) | `IsOffice = $true` |
| Deteksi: SSID cocok | `IsOffice = $true` |
| Deteksi: tidak ada rule cocok | `IsOffice = $false` |
| Deteksi: rule kosong | `IsOffice = $false` |
| Deteksi: domainJoined rule true tapi mesin workgroup | `IsOffice = $false` |
| Desired policy office | mode `automatic`, templates kosong |
| Desired policy outside | mode `secure`, templates Google |
| Registry round-trip di key sementara `HKCU:\Software\DoHSwitchTest\<guid>` | Set lalu Get sama; office menghapus value templates; Remove menghapus key |
| `Test-PolicyMatches` | sama = true, beda mode = false, beda templates = false |
| Config: file tidak ada | pakai default tanpa error |
| Config: field hilang | default terisi |

### 9.2 Integration test (dijalankan di mesin ini, 2026-10-13)

| Langkah | Ekspektasi | Hasil |
|---|---|---|
| Pester unit test | semua hijau | **27 passed, 0 failed** |
| `-Status` sebelum apa pun | Policy HKCU/HKLM kosong, deteksi ditampilkan | OK, deteksi `office` via `dnsServer=192.168.20.3, dnsSuffix=lan` |
| `-Apply -DryRun` (tanpa admin) | Tidak ada perubahan registry | OK, key tetap tidak ada |
| `-Apply` tanpa admin | exit `4` | OK |
| `-Apply -Force Outside` (admin) | `HKCU:\...\Chrome` berisi `DnsOverHttpsMode=secure`, templates Google | OK, dibaca ulang dari registry |
| `-Apply -Force Outside` kedua kali | Log "No change" | OK |
| `-Apply -Force Office` (admin) | `DnsOverHttpsMode=automatic`, value templates hilang | OK, hanya value `DnsOverHttpsMode` tersisa |
| `-Apply` auto (admin) | Mengikuti deteksi, tidak menulis jika sama | OK, "No change" |
| `-Reset` (admin) | Value hilang, key hilang jika kosong | OK, key absent |
| `chrome://policy` menampilkan policy; `chrome://settings/security` terkunci | | **Belum, manual oleh user** (extension tidak bisa buka `chrome://`) |
| `-InstallTask` lalu `Start-ScheduledTask` | Task ada, log bertambah | **Belum, tunggu OQ-1** |
| Logout/login di kantor dan di luar | Log berisi run baru dalam 1 menit setelah logon, profil benar | **Belum, user** |

Mesin dikembalikan ke kondisi awal setelah test (tidak ada policy DoH di HKCU/HKLM).

---

## 10. Task yang Harus Dikerjakan

| # | Task | Status |
|---|---|---|
| T1 | Tulis `DoHSwitch.ps1` dengan semua fungsi bagian 7 | Done |
| T2 | Tulis `config.json` default | Done |
| T3 | Tulis Pester test bagian 9.1 dan jalankan hijau | Done, 27/27 |
| T4 | Integration test `-Status`, `-DryRun`, `-Force Outside`, `-Force Office`, `-Reset` di mesin ini (elevated) | Done, lihat 9.2 |
| T4b | Guard elevasi + task `RunLevel Highest` setelah temuan ACL `HKCU\SOFTWARE\Policies` | Done |
| T5 | Verifikasi Chrome membaca policy HKCU di `chrome://policy` dan UI terkunci | **User**: admin PowerShell, `.\DoHSwitch.ps1 -Apply -Force Outside`, buka `chrome://policy`, lalu `-Reset` |
| T6 | Konfirmasi rule jaringan kantor (OQ-1), update `config.json` | **User** |
| T7 | Jalankan `-InstallTask -OnNetworkChange` dari PowerShell admin setelah T6 | **User** |
| T8 | Uji logout/login di kantor dan di luar kantor | **User** |
| T9 | (Opsional) `-InstallTask -OnNetworkChange` | User |
| T10 | (Backlog) rule resolve host internal, dukungan Edge/Brave | Backlog |

---

## 11. Risiko

| Risiko | Mitigasi |
|---|---|
| Rule kantor salah: di kantor terdeteksi "outside" → Google DoH `secure` → nama host internal gagal resolve | Konfirmasi OQ-1 dulu sebelum `-InstallTask`. `-Status` untuk cek cepat. `-Reset` sebagai escape hatch |
| Gateway `192.168.1.1` juga umum di rumah | Jangan pakai gateway sebagai satu-satunya rule; utamakan DNS server internal |
| Chrome mengabaikan policy registry non-GPO pada mesin unmanaged untuk policy "sensitif" | Policy DoH tidak ada di daftar sensitif; T5 memverifikasi |
| GPO enterprise di HKLM menimpa HKCU | FR-13 memberi peringatan |
| Task logon jalan sebelum jaringan siap | Delay 30 detik; task network-change sebagai pelengkap |
| Mode `secure` dan Google DoH diblokir di jaringan tertentu | Ubah `outside.mode` ke `automatic` di config jika perlu |

---

## 12. Open Questions

| ID | Pertanyaan | Rekomendasi |
|---|---|---|
| OQ-1 | Apakah jaringan dengan DNS `192.168.20.3` dan suffix `lan` adalah jaringan kantor? | **Resolved 2026-10-13: ya, konfirmasi user.** `config.json` sudah benar |
| OQ-2 | Perlu trigger network-change selain logon? | Ya, pasang `-OnNetworkChange` agar pindah WiFi tanpa restart ikut tertangani |
| OQ-3 | `outside.mode` tetap `secure` (ketat) atau `automatic`? | `secure`, sesuai pilihan UI "With Google (Public DNS)" |
