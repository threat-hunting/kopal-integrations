# SOCLib SOAR – Kopal Integration

پروژهٔ یکپارچه‌سازی Kopal با ابزارها و سرویس‌های مختلف (با الهام از Splunk SOAR). تمام کدهای توسعه در این ریپو قرار دارند. مستندات و طراحی در پوشهٔ **doc** خارج از ریپو نگهداری می‌شوند: `../doc/` (همسطح با این ریپو در پوشهٔ GitHub). **ساختار و نام‌گذاری (پیشوند soclib، مسیر قالب‌ها، namespace)** الزامی است — رجوع به `../doc/CONVENTIONS.md`.

---

*Based on Kopal Starter Kit.* Click on `Use this template` to copy Kopal's custom integrations starter kit.

This starter kit contains:
- `pyproject.toml` config file
- Example Python UDFs (user defined functions) in `mapping.py` and `greetings.py`
- An example Action Template in `custom_actions/templates/power_of_three.yml`.

## Development

> [!IMPORTANT]
> Check out the tutorial on building and syncing custom integrations in our [docs here](https://docs.kopal.com/tutorials/custom-integrations).

> [!NOTE]
> When setting your git URL, the correct scheme is: `git+ssh://git@github.com/<username>/<repo>.git` (notice the "/<username>" not ":<username>")

**Note:**
- You can safely delete example Python integrations files and templates under `custom_actions/`
- **Do not** remove `pyproject.toml`. This is required for your Kopal instance to install and run your custom integrations.
- You can add 3rd party `pip` packages (e.g. `psycopg==3.2.4`) in the `pyproject.toml` file under [`project.dependencies` here](https://github.com/KopalHQ/custom-integrations-starter-kit/blob/main/pyproject.toml#L11).
- The `dev` dependency group installs **pytest** only. The `kopal_registry` package is **not** a pip dependency — Kopal provides it at runtime; local tests use a lightweight stub in `tests/kopal_registry_stub.py`.

> [!TIP]
> We recommend following Kopal's open source [integrations](https://github.com/KopalHQ/kopal/tree/main/registry/kopal_registry) for inspiration and guidance.

### Testing SOCLib AD actions (tools.soclib.ad)

1. **سکرت در Kopal:** در Organization → Secrets یک سکرت با نام `soclib_active_directory` بسازید و کلیدها را پر کنید:
   - `AD_URL` — آدرس سرور: `ldap://IP` یا `IP` یا `IP:389` (بدون SSL)؛ `ldaps://IP:636` (با SSL)
   - `AD_BIND_DN` — DN یا UPN کاربر bind
   - `AD_BIND_PASSWORD` — رمز
   - `AD_BASE_DN` — DN پایه جستجو (مثلاً `DC=corp,DC=local`)

2. **اتصال ریپو به Kopal:**
   - **توسعهٔ محلی:** در `.env` Kopal قرار دهید:
     - `KOPAL__LOCAL_REPOSITORY_ENABLED=true`
     - `KOPAL__LOCAL_REPOSITORY_PATH=<مسیر مطلق به این ریپو>`
   - **Production:** در Organization → Git repository آدرس این ریپو را تنظیم و از Registry → Repositories دکمه Sync بزنید.

3. **تست در UI:** در یک Workflow اکشن‌های زیر را اضافه و اجرا کنید:
   - `tools.soclib.ad.test_connectivity` (بدون ورودی)
   - `tools.soclib.ad.user_get` با ورودی `username`
   - `tools.soclib.ad.run_query` با `filter` (مثلاً `(objectClass=user)`)، `attributes` (مثلاً `sAMAccountName;mail`)

4. **اعتبارسنجی قالب‌های YAML (در ریشهٔ ریپو):**
   ```bash
   uv run tc validate template custom_actions/templates
   ```
   در صورت نصب نبودن: `pip install -e ".[dev]"` یا وابستگی dev را در `pyproject.toml` اضافه کنید.

**لیست اکشن‌های AD (۱۳ عدد):** test_connectivity, run_query, get_attributes, user_get, add_group_members, remove_group_members, unlock_account, disable_account, enable_account, reset_password, set_password, move_object, set_attribute, rename_object. همه خروجی استاندارد `{ success, data, error, meta }` برمی‌گردانند.

**استفاده از داده‌های خروجی در Workflow:** برای ارجاع به فیلدها، استخراج از آرایه، و Loop — رجوع به `../doc/reference/data-usage-in-workflows.md`.

#### رفع خطای `invalidCredentials` (LDAP bind)

اگر `LDAPBindError: automatic bind not successful - invalidCredentials` دریافت کردید، فرمت سکرت‌ها را بررسی کنید:

| کلید | فرمت صحیح | مثال اشتباه |
|------|------------|-------------|
| **AD_URL** | `ldap://IP` یا `IP` یا `IP:389` (بدون SSL) | `***` (masked؛ مقدار واقعی باید host یا URL صحیح باشد) |
| **AD_BIND_DN** | **UPN** (`user@domain.com`) یا **DN کامل** | فقط `administrator` (اکثر ADها قبول نمی‌کنند) |
| **AD_BASE_DN** | DN دامنه (مثلاً `DC=lab,DC=local`) | خالی یا اشتباه |

مثال صحیح برای IP `192.168.11.62` و دامنه `soclib.local`:
```
AD_URL=192.168.11.62
AD_BIND_DN=administrator@soclib.local
AD_BIND_PASSWORD=<stored-in-Kopal-secret-store>
AD_BASE_DN=DC=soclib,DC=local
```

اگر UPN قبول نشد، از DN کامل استفاده کنید:
```
AD_BIND_DN=CN=Administrator,CN=Users,DC=soclib,DC=local
```

#### رفع خطای `LDAPSocketOpenError: invalid server address`

این خطا گاهی به‌خاطر **auto_referrals** در ldap3 رخ می‌دهد (کد ما اکنون `auto_referrals=False` دارد). در غیر این صورت، مقدار `AD_URL` را بررسی کنید. فرمت‌های پذیرفته:
- `192.168.11.62` → host به‌صورت پیش‌فرض با پورت 389
- `ldap://192.168.11.62` یا `ldap://192.168.11.62:389` → بدون SSL  
- `ldaps://192.168.11.62:636` → با SSL

#### نام سکرت و چند Active Directory

| سؤال | پاسخ |
|------|------|
| **نام سکرت** | `soclib_active_directory` — **استاتیک**؛ توسط integration تعریف شده و نباید تغییر کند. |
| **چندین AD** | می‌توانید چند Credential جداگانه با همین نام بسازید (مثلاً «AD Lab»، «AD Prod»)؛ هر اکشن در Workflow یکی از آن‌ها را انتخاب می‌کند. |
| **انتخابی روی چند AD** | بله؛ در هر Workflow برای هر اکشن می‌توانید Credential متفاوت انتخاب کنید. |

#### تست محلی (بدون Kopal)

برای تست اتصال مستقیم به AD (با Python و ldap3):

```bash
cd soclib-soar-integration
pip install ldap3
python scripts/test_ad_connection.py 192.168.11.62
```

خروجی‌های مورد انتظار: با پسورد صحیح OK، با پسورد اشتباه FAIL.

---

### Renaming the package
If you want to rename `custom_actions` to `<your_registry_name>`, you must:
- Pick a package name that is in snakecase
- Rename the `custom_actions` directory to `<your_registry_name>`
- Change every `custom_actions` directory name in `pyproject.toml` to `<your_registry_name>`   

For example:

```bash
cd custom-integrations-starter-kit
mv custom_actions my_custom_integrations
sed -i 's/custom_actions/my_custom_integrations/g' pyproject.toml
``` 
