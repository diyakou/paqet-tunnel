# اسکریپت نصب و مدیریت KYPAQET

این پروژه یک اسکریپت Bash برای نصب، کانفیگ و مدیریت تانل `paqet` است.
سناریوی اصلی:
- **Server (خارج)**: دریافت اتصال از ایران
- **Client (ایران)**: اتصال به سرور خارج و ارائه SOCKS5 یا Port Forward

---

## پیش‌نیازها

- سیستم‌عامل لینوکس (Ubuntu / Debian / CentOS / RHEL / Rocky / Alma / Arch)
- دسترسی `root` یا `sudo`
- باز بودن پورت سرویس روی سرور خارج
- نصب بودن `curl` یا `wget` (در صورت نبود، اسکریپت تلاش می‌کند نصب کند)

نکته:
- اسکریپت باینری را از ریپوی اصلی دانلود می‌کند: `https://github.com/diyakou/paqet`

---

## نصب سریع

روی **هر دو سرور (ایران و خارج)** اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/diyakou/paqet-tunnel/master/deploy-tunnel.sh -o deploy.sh && chmod +x deploy.sh && sudo ./deploy.sh
```

---

## آموزش کامل نصب (مرحله‌به‌مرحله)

## 1) نصب سمت خارج (Server)

1. اسکریپت را اجرا کنید:

```bash
sudo ./deploy.sh
```

2. در منو گزینه `Single Tunnel` را انتخاب کنید.
3. نقش را `server` انتخاب کنید.
4. اطلاعات شبکه را طبق سرور وارد کنید:
- `interface` (مثل `eth0` یا `ens3`)
- `listen port` (مثلا `9999`)
- `router mac` (در صورت نیاز)
5. کلید رمزنگاری را ذخیره کنید (یا کلید دلخواه خودتان را وارد کنید).
6. پس از پایان، اسکریپت:
- فایل کانفیگ می‌سازد
- Ruleهای فایروال لازم را اعمال می‌کند
- سرویس systemd می‌سازد و اجرا می‌کند

بررسی وضعیت سرویس:

```bash
sudo systemctl status paqet-server
```

(اگر نام سرویس سفارشی باشد، از `sudo ./deploy.sh --status` استفاده کنید.)

---

## 2) نصب سمت ایران (Client)

1. اسکریپت را اجرا کنید:

```bash
sudo ./deploy.sh
```

2. گزینه `Single Tunnel` را انتخاب کنید.
3. نقش را `client` انتخاب کنید.
4. اطلاعات زیر را وارد کنید:
- IP یا دامنه سرور خارج
- پورت سرور خارج
- **همان کلید رمزنگاری** که روی سرور تنظیم شده
5. نوع خروجی را انتخاب کنید:
- `SOCKS5` (پیش‌فرض: `127.0.0.1:1080`)
- یا `Port Forward`
6. در پایان سرویس ساخته و اجرا می‌شود.

بررسی وضعیت:

```bash
sudo systemctl status paqet-client
```

(یا از `sudo ./deploy.sh --status` برای لیست کامل سرویس‌ها استفاده کنید.)

---

## تست اتصال

اگر روی کلاینت خروجی SOCKS5 دارید:

```bash
curl -v https://httpbin.org/ip --proxy socks5h://127.0.0.1:1080
```

اگر IP خروجی، IP سرور خارج بود یعنی تانل درست کار می‌کند.

---

## دستورات مدیریت

پس از نصب می‌توانید اسکریپت را به‌صورت سراسری نصب کنید:

```bash
sudo ./deploy.sh --install
```

سپس:

```bash
sudo paqet --status
sudo paqet --manage
sudo paqet --logs
sudo paqet --errors
sudo paqet --restart-all
sudo paqet --stop-all
sudo paqet --start-all
sudo paqet --update-core
```

حذف اسکریپت سراسری:

```bash
sudo paqet --uninstall
```

---

## تنظیمات پیشنهادی برای پایداری

- KCP mode: `fast2`
- تعداد کانکشن: `3`
- Window پیش‌فرض:
- Client: `2048`
- Server: `4096`
- MTU پیشنهادی:
- لینک پایدار: `1280` تا `1350`
- لینک محدود/ناپایدار: `1200` تا `1280`

---

## عیب‌یابی سریع

1. سرویس بالا نمی‌آید:

```bash
sudo journalctl -u paqet-client -n 100 --no-pager
sudo journalctl -u paqet-server -n 100 --no-pager
```

2. قطع و وصل دوره‌ای دارید:
- MTU را پایین‌تر تنظیم کنید (مثلا `1240`)
- تعداد کانکشن را خیلی بالا نبرید
- Ruleهای فایروال را دوباره اعمال کنید

3. اتصال برقرار نمی‌شود:
- کلید رمزنگاری دو سمت باید یکسان باشد
- IP/Port صحیح باشد
- Security Group / Firewall سرور پورت را باز کرده باشد

---

## لایسنس

این اسکریپت برای استفاده عملیاتی و شخصی ارائه شده است.
