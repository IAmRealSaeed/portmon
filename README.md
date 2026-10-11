<div dir="rtl">

# portmon

داشبورد وب فارسی برای دیدن **مصرف ترافیک هر پورت** و **منابع سرور**، مخصوص سرورهای تانل/رله و هر سرور لینوکسی که چند سرویس روی پورت‌های مختلف دارد.

یک فایل پایتون است، فقط با کتابخانهٔ استاندارد، و جز `nft` و `python3` چیزی لازم ندارد. نه دیتابیس جدا، نه وب‌سرور جدا، نه pip.

> **English:** portmon is a single-file, stdlib-only Python dashboard (Persian UI) that counts traffic per TCP/UDP port
> with nftables, groups ports, and shows usage per day/hour plus live server resources. Install on Debian/Ubuntu with
> `curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/install.sh | sudo bash`.

## امکانات

- شمارش دانلود و آپلود هر پورت با nftables. قوانین فقط می‌شمارند و هیچ بسته‌ای را رد یا قبول نمی‌کنند.
- گروه‌بندی پورت‌ها؛ هر پورت می‌تواند در چند گروه باشد. مجموع «همهٔ پورت‌ها» هر پورت را یک بار حساب می‌کند.
- گزارش امروز، دیروز، ۷، ۳۰ و ۹۰ روز یا هر بازهٔ دلخواه، با تاریخ شمسی و نمودار روزانه یا ساعتی.
- سرعت لحظه‌ای هر پورت و هر گروه.
- منابع سرور: پردازنده، رم، سواپ، دیسک، شبکهٔ کارت اصلی، تعداد اتصال‌ها و conntrack، و پرمصرف‌ترین برنامه‌ها.
- ورود با رمز (هش PBKDF2)، HTTPS با گواهی خودامضا، و قفل موقت بعد از ۸ بار رمز اشتباه.
- نگهداری داده: دقیقه‌ای ۳ روز، ساعتی ۹۰ روز، روزانه برای همیشه، منابع سرور ۷ روز.

## پیش‌نیازها

- Debian 11 به بالا یا Ubuntu 20.04 به بالا (هر توزیعی با systemd، `nft` و `python3` به‌جز نصب‌کنندهٔ apt هم کار می‌کند)
- دسترسی root
- یک پورت آزاد برای داشبورد (پیش‌فرض `8800`)

## نصب

### روش ۱: یک دستور (سرور به GitHub دسترسی دارد)

```bash
curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/install.sh | sudo bash
```

نصب‌کننده رمز داشبورد را می‌پرسد. بعد آدرس `https://IP-سرور:8800` را باز کنید. چون گواهی خودامضاست، مرورگر یک بار هشدار می‌دهد که باید قبولش کنید.

برای نصب بدون سؤال، مثلاً در اسکریپت، رمز و پورت را با متغیر محیطی بدهید:

```bash
curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/install.sh | sudo PM_PASSWORD='رمز-قوی' PM_PORT=9443 bash
```

### روش ۲: از روی کلون

```bash
git clone https://github.com/IAmRealSaeed/portmon.git && cd portmon && sudo ./install.sh
```

### روش ۳: آفلاین (سرور به GitHub دسترسی ندارد)

فایل `install_portmon.sh` را از بخش [Releases](https://github.com/IAmRealSaeed/portmon/releases/latest) دانلود کنید. برنامه و فونت‌ها داخل همین فایل‌اند. فایل را به سرور منتقل کنید و اجرا کنید:

```bash
scp install_portmon.sh root@SERVER:/root/
```

```bash
sudo bash install_portmon.sh
```

اگر کد را تغییر دادید، همین فایل را خودتان با `python3 make_installer.py` بسازید. خروجی در `dist/install_portmon.sh` ذخیره می‌شود.

### تنظیمات نصب

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `PM_PASSWORD` | می‌پرسد | رمز داشبورد، حداقل ۸ کاراکتر. موقع به‌روزرسانی خالی بگذارید تا رمز قبلی بماند. |
| `PM_PORT` | `8800` | پورت داشبورد |
| `PM_AUTOADD` | `1` | در نصب اول همهٔ پورت‌های TCP عمومی را که روی سرور گوش می‌دهند زیر نظر می‌گیرد، به‌جز ۲۲، ۵۳ و پورت داشبورد. `0` یعنی با لیست خالی شروع شود. |

> اگر فایروال (ufw، فایروال دیتاسنتر و غیره) دارید، پورت داشبورد را باز کنید. بهتر است فقط برای IP خودتان باز باشد.

## به‌روزرسانی

همان دستور نصب را دوباره اجرا کنید. داده‌ها، گروه‌ها، تنظیمات و رمز می‌مانند.

## حذف

```bash
curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/uninstall.sh | sudo bash
```

این دستور سرویس، جدول nftables و `/opt/portmon` را پاک می‌کند، ولی تنظیمات و آمار را نگه می‌دارد. برای پاک کردن همه‌چیز:

```bash
curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/uninstall.sh | sudo PM_PURGE=1 bash
```

## مدیریت

| کار | دستور |
|---|---|
| وضعیت سرویس | `systemctl status portmon` |
| لاگ‌ها | `journalctl -u portmon -f` |
| ری‌استارت | `systemctl restart portmon` |
| رمز جدید (اگر یادتان رفته) | `read -rs P && echo "$P" \| sudo python3 /opt/portmon/portmon.py --set-password && sudo systemctl restart portmon` |
| دیدن جدول شمارش | `nft list table inet portmon` |

رمز را از تب «تنظیمات» داشبورد هم می‌شود عوض کرد. افزودن و حذف پورت و ساختن گروه هم از همان‌جا انجام می‌شود.

## فایل‌ها روی سرور

| مسیر | محتوا |
|---|---|
| `/opt/portmon/` | برنامه و فونت‌ها |
| `/etc/portmon/config.json` | تنظیمات و هش رمز (دسترسی ۶۰۰) |
| `/etc/portmon/cert.pem`، `key.pem` | گواهی خودامضا (ده‌ساله) |
| `/var/lib/portmon/portmon.db` | آمار (SQLite) |

کلیدهای `config.json`:

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `listen` | `0.0.0.0` | آدرس گوش دادن. با `127.0.0.1` داشبورد فقط از طریق تونل SSH باز می‌شود. |
| `port` | `8800` | پورت داشبورد |
| `interval` | `60` | فاصلهٔ نمونه‌برداری (ثانیه) |
| `utc_offset_minutes` | `210` | اختلاف ساعت محلی با UTC برای مرز روز و ساعت (۲۱۰ = تهران) |
| `title` | `مصرف پورت‌ها` | عنوان صفحه |
| `tls_cert`، `tls_key` | گواهی خودامضا | برای گواهی واقعی، مسیرهای خودتان را بگذارید. خالی یعنی HTTP. |

بعد از تغییر این فایل، `systemctl restart portmon` را اجرا کنید.

## شمارش چطور کار می‌کند

برای هر پورت P، بایت‌های اتصال‌هایی شمرده می‌شود که **مقصد اصلی‌شان** P است. ترافیک کاربر به سرور آپلود و ترافیک سرور به کاربر دانلود حساب می‌شود. شمارش با conntrack (`ct original proto-dst`) در زنجیره‌های input، output و forward انجام می‌شود. برای همین اتصال خروجی خود رله به سرور مقصد، حتی اگر از همان شمارهٔ پورت استفاده کند، شمرده نمی‌شود.

عددها بایت شبکه‌اند، یعنی سرآیند IP و TCP/UDP هم حساب می‌شود. برای همین معمولاً چند درصد از عددی که پنل VPN برای همان ترافیک نشان می‌دهد بیشترند.

جدول `inet portmon` جدا از قوانین فایروال شماست و چیزی را تغییر نمی‌دهد. اگر `nftables.service` فعال باشد و قوانین را از نو بارگذاری کند، portmon جدولش را در نمونه‌برداری بعدی دوباره می‌سازد.

## امنیت

- داشبورد را پشت فایروال نگه دارید، یا `listen` را `127.0.0.1` کنید و با `ssh -L 8800:127.0.0.1:8800 root@SERVER` باز کنید.
- رمز قوی بگذارید. نشست ورود ۱۴ روز اعتبار دارد.
- `config.json` هش رمز و کلید امضای نشست را دارد. آن را جایی منتشر نکنید.

## مجوز

کد با مجوز [MIT](LICENSE). فونت [وزیرمتن](https://github.com/rastikerdar/vazirmatn) با مجوز [SIL OFL 1.1](fonts/OFL.txt).

</div>
