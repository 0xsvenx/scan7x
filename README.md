# scan7x

**Pull a bug-bounty program's scope, then recon it — in one command.**
Pick a platform (HackerOne / Bugcrowd / Intigriti / YesWeHack), type a target
(e.g. `red bull`), choose what to pull (domains / APIs / wildcards / …), and
scan7x downloads the scope, enumerates subdomains, probes live hosts,
harvests JavaScript, extracts endpoints, and writes a clean report — all in Go,
with **zero external dependencies** and **no API keys required**.

```text
  ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚════██║╚██╗██╔╝
  ███████╗██║     ███████║██╔██╗ ██║    ██╔╝ ╚███╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║   ██╔╝  ██╔██╗
  ███████║╚██████╗██║  ██║██║ ╚████║   ██║  ██╔╝ ██╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝  ╚═╝  ╚═╝
        bug-bounty recon & enumeration engine
```

---

## المميزات (Features)

- 🎯 **اختيار المنصة والتارقت**: HackerOne و Bugcrowd و Intigriti و YesWeHack.
- 🗂️ **تصنيف تلقائي للـ scope**: نطاقات، wildcards، APIs، تطبيقات جوال، CIDR، سورس، وأخرى — كل نوع بملف مستقل.
- 🔎 **جمع subdomains بشكل passive** من عدة مصادر: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX.
- 🌐 **فحص المضيفين الأحياء** (probe) مع رمز الحالة والعنوان (title).
- 🕸️ **جمع الروابط من Wayback** + استخراج ملفات **JavaScript** وتنزيلها.
- 🧩 **استخراج الـ endpoints** من ملفات الـ JS (مسارات وروابط API).
- 📄 **تقرير نهائي مرتب** (`report.md` + `summary.json`) ومجلدات منظمة.
- 🧱 مبني بلغة **Go**، بدون أي مكتبات خارجية، ويشتغل على Windows/Linux/macOS.

---

## المتطلبات والتثبيت (Install)

يحتاج فقط **Go 1.22+**. حمّله من <https://go.dev/dl/>.

```bash
git clone https://github.com/<your-username>/scan7x.git
cd scan7x
go build -o scan7x ./...      # على ويندوز: go build -o scan7x.exe ./...
```

بعد البناء تحصل ملف تنفيذي واحد اسمه `scan7x` (أو `scan7x.exe`).

> اختياري: لتفعيل `go install github.com/<your-username>/scan7x@latest`
> عدّل أول سطر في `go.mod` ليطابق رابط مستودعك.

---

## البدء السريع (Quick start)

### 1) الوضع التفاعلي (الأسهل)

شغّل الأداة بدون أي خيارات وتمشّي معك خطوة بخطوة:

```bash
./scan7x
```

```
Select platform:
  1) all
  2) hackerone
  3) bugcrowd
  4) intigriti
  5) yeswehack
Choice [1]: 3

Enter target program name (e.g. red bull): red bull

Scope found:
   - domains    12
   - wildcards  4
   - apis       2

What to pull? comma list (domains,apis,wildcards,...) or 'all'
Choice [all]: all

Recon depth:
  1) scope    — only download & categorize scope
  2) passive  — scope + passive subdomain enum + Wayback JS list
  3) full     — enum + live probe + crawl + download JS + endpoints
Choice [3]: 3
```

### 2) بالخيارات (للأتمتة)

```bash
# ابحث في كل المنصات عن "red bull" وسوِّ recon كامل
./scan7x -target "red bull"

# HackerOne فقط، اسحب النطاقات والـ wildcards، recon passive
./scan7x -platform hackerone -target uber -pull domains,wildcards -recon passive

# فقط اسحب وصنّف الـ scope بدون أي recon
./scan7x -target shopify -recon scope

# تخطَّ البحث في المنصات وسوِّ recon مباشرة على نطاقات تعرفها
./scan7x -root example.com,api.example.com -recon full -o ./out/example
```

---

## كيف تشتغل (The flow)

```
platform + target  ─▶  scope (categorized)  ─▶  enumeration  ─▶  live probe
                                                      │
                                                      ▼
   report.md  ◀─  endpoints  ◀─  download JS  ◀─  Wayback URLs + crawl
```

1. **Scope**: تُجلب بيانات البرامج من مشروع `bounty-targets-data` (محدّث يوميًا،
   بدون مفاتيح) وتُصنّف الأصول تلقائيًا. الـ scope يُكاش محليًا 24 ساعة (`-refresh` لإجباره).
2. **Enumeration**: تُجمع الـ subdomains للـ **wildcard roots** فقط (مثل `*.example.com`)
   من مصادر passive. المضيفون المحددون بدون wildcard لا يُوسّعون (حفاظًا على النطاق).
3. **Probe** (في وضع `full`): فحص كل مضيف عبر HTTPS ثم HTTP وتسجيل الأحياء.
4. **URLs + JS**: جمع الروابط من Wayback + زحف صفحات المضيفين الأحياء لاستخراج
   `<script src>`، ثم تنزيل ملفات الـ JS داخل النطاق واستخراج الـ endpoints منها.
5. **Report**: كتابة تقرير وملخّص ومجلدات مرتبة.

---

## الخيارات (Flags)

| الخيار | الافتراضي | الوصف |
|---|---|---|
| `-platform` | `all` | `hackerone` \| `bugcrowd` \| `intigriti` \| `yeswehack` \| `all` |
| `-target` | — | اسم/هاندل البرنامج للبحث (مثل `"red bull"`) |
| `-pull` | `all` | فئات الـ scope: `domains,wildcards,apis,mobile,cidr,source,other,all` |
| `-pick` | `0` | عند تعدّد النتائج، اختر الرقم N |
| `-recon` | `full` | `scope` \| `passive` \| `full` |
| `-o` | `./output/<platform>_<handle>` | مجلد الإخراج |
| `-root` | — | تخطَّ الـ scope وسوِّ recon مباشرة على نطاقات (قائمة مفصولة بفواصل) |
| `-sources` | `certspotter,crtsh,hackertarget,rapiddns,otx` | مصادر الـ subdomains |
| `-threads` | `25` | مستوى التوازي للفحص/الزحف/التنزيل |
| `-timeout` | `15` | مهلة كل طلب بالثواني عند لمس الأهداف |
| `-wayback-limit` | `20000` | أقصى عدد روابط لكل هدف من Wayback (0 = بلا حد) |
| `-refresh` | `false` | إجبار تحديث كاش بيانات الـ scope |
| `-y` | `false` | وضع غير تفاعلي (لا أسئلة) |
| `-version` | — | اطبع الإصدار واخرج |

---

## هيكل المخرجات (Output layout)

```
output/<platform>_<handle>/
├─ report.md                 ← التقرير النهائي المقروء
├─ summary.json              ← ملخّص بصيغة JSON (أرقام + مسارات)
├─ scope/
│   ├─ domains.txt
│   ├─ wildcards.txt
│   ├─ apis.txt
│   ├─ mobile.txt / cidr.txt / source.txt / other.txt
│   ├─ roots.txt             ← جذور الـ wildcards المستخدمة للـ enumeration
│   └─ raw_program.json      ← الـ scope الكامل المطبّع
├─ subdomains/all.txt        ← كل الـ subdomains المكتشفة
├─ live/
│   ├─ live_hosts.txt        ← status + url + title
│   └─ live_urls.txt
├─ urls/
│   ├─ all_urls.txt          ← روابط Wayback + الزحف
│   └─ js_urls.txt
└─ js/
    ├─ <host>_<file>.js      ← ملفات JS المنزّلة (بلا تكرار)
    └─ endpoints.txt         ← الـ endpoints المستخرجة
```

---

## مصادر البيانات (Data sources)

كلها عامة ولا تحتاج مفاتيح:

- **Scope**: [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data) (يجمع نطاقات HackerOne/Bugcrowd/Intigriti/YesWeHack العامة يوميًا).
- **Subdomains**: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX.
- **URLs/JS**: Wayback Machine (web.archive.org) + زحف مباشر خفيف.

المصادر ذات الحدود (rate limits) تُعالَج بلطف: إذا تعطّل مصدر أو تجاوز الحد،
تُكمل الأداة من البقية بدون توقّف.

---

## استخدام مسؤول (Responsible use) ⚠️

هذه أداة **استطلاع (recon)** للاستخدام في برامج مكافآت الثغرات المصرّح بها.

- تعامل فقط مع الأصول **الموجودة صراحةً ضمن نطاق** البرنامج، والتزم بسياسته وحدوده.
- الاستطلاع **ليس تصريحًا بالاستغلال**.
- معظم الخطوات passive (سجلّات الشهادات/الأرشيف)، لكن الفحص وتنزيل الـ JS يرسلان
  طلبات HTTP خفيفة للأهداف — استخدمها فقط حيث لديك إذن.

المسؤولية القانونية على المستخدم.

---

## كيف اختُبرت (Tested)

- `go vet ./...` و `gofmt` نظيفة، و `go test ./...` (اختبارات وحدة للتحليل والتصنيف والتنقية) تنجح.
- تشغيل كامل حقيقي على `owasp.org`: 56 subdomain، 55 live host، 156 ملف JS،
  و572 endpoint مستخرجة — مع تعامل سليم عند تعطّل بعض المصادر.

---

## License

[MIT](LICENSE)
