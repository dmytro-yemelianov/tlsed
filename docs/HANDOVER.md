# TLSed — handover, 2026-10-14

## Оновлення 2026-10-14 (після Aeneas)

**Коміти** на гілці `general-workspace-task-d698612e` (решта робочого дерева лишається untracked):
- `bc96079` tls-core: aligned wipes і block-skip inner scan (`protected.rs`).
- `c3591d5` tls-crypto-awslc: aligned erasure на error-шляхах seal/open.
- `579e723` tls-bench: cursor-транспорт замість `Vec::drain`; rerun fragment-64.
- `53d39dd` експерименти та результати: inner-scan-audit, wipe-scan-candidates, openssl-compare (+ extended, p256-hrr-12).
- Наступний коміт: ретрансляція tls-core під landed `protected.rs` (маніфест і generated).

**Виміряно** (AES-128-GCM, X25519, Apple M5; переміри landed-бінарника ще немає):
- 1 B + 16 383 нулів: 9.6 → 2.1 µs (0.22×). Bad tag, 16 KiB: 9.9 → 2.5 µs (0.25×). Звичайні записи без змін.
- TLSed vs rustls: handshake паритет (0.98–1.03); bulk 16 KiB server→client 0.86; fragment-64 server→client 0.62; client→server fragment-64 0.74.
- TLSed vs OpenSSL 3.6.5: handshake ~0.65; bulk 16 KiB client→server 0.78; ChaCha bulk паритет з OpenSSL.

**Застарілі твердження нижче в цьому файлі й у попередніх звітах:**
- Fragment-64 TLSed vs rustls 0.70–0.84 (cpu-audit frozen baseline, `tls-bench/results/2026-10-14-client-comparison`): вимірено через drain-транспорт, не валідно. Виправлено в `2026-10-14-client-comparison-transport-fixed`. Старий каталог не відтворюється з поточного дерева; не цитувати.
- Усі порівняння з OpenSSL до виправлень shim і транспорту: застарілі, див. `verification/results/2026-10-14-openssl-compare/README.md`, розділ Corrections.
- «Жодних комітів» більше не актуально.

**Aeneas.** Charon `c8f15d7d` (toolchain `nightly-2026-09-17`) і Aeneas `557eff83` зібрано з pinned commits у scratch, не в репо. Регенерація:
`RUSTUP_TOOLCHAIN=nightly-2026-09-17 CHARON_BIN=… AENEAS_BIN=… python3 verification/check_translation.py --regenerate`.
Скрипт очікує 8-символьний префікс версії Aeneas, тому в клоні Aeneas треба `git config core.abbrev 8`, інакше `-version` дає 7 символів і перевірка відмовляє. Попередню копію `TlsCore.lean` перезаписано без diff; у новому генерованому файлі немає `wipe`/`last_nonzero`. `check_translation.py` проходить; `lake build` у `verification/aeneas`: 1728 jobs, без помилок і `sorry`.

**Зроблено після цього оновлення:**
- Landed-бінарник переміряно проти pre-landing збірки (`verification/results/2026-10-14-landed-check`, парний): padmax 0.22×, bad tag 16 KiB 0.25×, 4 KiB padding 0.29×, 1 KiB padding 0.37×. Довгі й короткі записи в межах шуму (~1.00).
- Профілі aes256, chacha, p256 і hrr у `tls-bench` перезапущено з виправленим транспортом (`crates/tls-bench/results/2026-10-14-client-comparison-transport-fixed-other`). Для більшості рядків зміна ≤5%. Винятки: AES-256 client→server 16 KiB (1.02 → 0.87, широкий діапазон) і lifecycle через фікс `Drop`.

**Відкрите:**
- Вирішити, чи лишати `verification/aeneas` (proof-файли) untracked; зараз закомічено лише згенероване.

---


Workspace: `/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e`.
Мова користувача — українська. Користувач просить конкретну роботу й вимірювання,
а не пропозицію продовжити. Для навігації кодом спочатку використовувати
codebase-memory-mcp (`search_graph`, `trace_path`, `get_code_snippet`), проект
`tlsed-foundation`; для конфігурацій, документації, рядкових літералів або
недостатнього графа — `rg`. Статистика графа не є runtime-профілем.

Останні запити: провести CPU/SIMD-аудит без змін production-коду; після результатів
«то втілюємо?»; потім «create handover». Аудит завершився без production-змін,
що зафіксовано хешами. Після окремої вказівки користувача перенесено лише
підтверджену оптимізацію `Reassembler::Drop`. NEON та розгортання циклу не перенесені.
Жодних комітів, push, PR або зовнішніх повідомлень не робили. Workspace історично
містить усі файли як untracked; не видаляти їх і не приймати цей стан за власний diff.

**Що внесено.** `crates/tls-core/src/handshake.rs`: Drop розбиває ВСЮ позичену
`self.scratch` на byte head / вирівняні u128 / byte tail через безпечний
`bytemuck::pod_align_to_mut`, потім кожну частину стирає `zeroize`. До
`crates/tls-core/Cargo.toml` додано вже використаний клієнтом
`bytemuck = "=1.25.2"`, `default-features = false`; відповідно оновлено lockfile.
Новий `crates/tls-core/tests/drop_wiping.rs` порівнює весь guarded-буфер із
незалежним `Vec::fill(0)` oracle: offsets 0..31, sizes 4..257 та межі до 65 540 B,
п'ять станів (unused, partial, malformed/failed, consumed, ready), cap менший за loan.
Конструктор Reassembler НЕ стирає handshake scratch. Тому скорочувати Drop до
`buffered` або `cap + 4` не можна. Fail/consume, конструктор, API й порядок помилок
не змінені. Звичайний fill не замінює compiler-resistant стирання секретів.

**Обмеження.** Експериментальна transport-independent TLS 1.3 бібліотека;
зараз реалізовано автентифікований client, HRR, application data, KeyUpdate,
alerts/closure; server, mTLS, OpenSSL endpoint interoperability та adapters відкриті.
Rust MSRV 1.98, pinned compiler 1.98.1, edition 2024, release thinLTO/codegen-units=1.
Own workspace `unsafe_code = "forbid"` збережений. `tls-core` і `tls-crypto` —
no_std без alloc; client/PKI/AWS-LC adapter використовують std/alloc. Зовнішні
safe wrappers/FFI/компілятор залишаються довіреною межею. Повний client не є no_std.
Виміряно Apple M5 / arm64 / macOS 27.2 / AC power. У специфікації потрібні також
x86-64 бенчі, але їх ще немає. Foundation із новим Drop компілюється для
wasm32-unknown-unknown без std/alloc; це portability check, не performance вимір.
Не підвищувати MSRV, не додавати own unsafe і не послаблювати PKI/secret erasure.

Client API позичає чотири caller buffers: мінімум 16 645 / 65 540 / 16 640 /
16 645 B (115 470 B разом), explicit name/time/config, incremental drive з
consumed/produced і backpressure. Authentication gates, nonce/key epoch discipline,
обмежені input/work та unread-plaintext semantics залишаються обов'язковими.

**Вердикт CPU-аудиту:** зміна структури стирання застосовна; новий SIMD умовний,
підтвердженого додаткового виграшу немає; переписувати вже прискорену криптографію
недоцільно. Позначення нижче: вимірювання / структурний факт / неперевірена гіпотеза.
Усі шляхи до evidence в наступній таблиці відносні до
`verification/results/2026-10-14-cpu-audit/`.

| Вузьке місце | Зміна | Ефект | Обмеження | Докази |
|---|---|---|---|---|
| Побайтний Drop 65 540 B | Safe aligned u128, full loan | **Вимір:** primitive 14.701 → 0.951 µs; AES lifecycle prototype 135.656 → 122.896 µs, median speedup 1.107× (repeat 1.021–1.120×), normalized 1.110×. ChaCha 1.119×; fragment64 1.117× | M5; виграш lifecycle, bulk суттєво не змінився; retained volatile erasure | `micro/comparison.csv`, `drop-u128/before-after.csv`, `asm/baseline-drop.txt`, `asm/prototype-drop-u128.txt` |
| Поточний u128 loop | Unroll 8 words | **Вимір:** 16 KiB primitive 235.636 → 113.770 ns, 2.071×. Full TLS raw TX/RX +4.2%/+2.5%, але normalized speedup 0.985×/0.979× — переконливий виграш не підтверджено | Aligned16 B primitive регресує 1.312 → 1.740 ns; не переносити за micro результатом | `micro/comparison.csv`, `block8/before-after.csv`, `block8-client.patch` |
| Scalar register stores | Safe NEON-type volatile stores | **Вимір:** 16 KiB 235.636 → 235.271 ns, paired 1.002× — практично однаково | AArch64/cfg+portable fallback, додаткова opt-in SIMD policy; full TLS не тестували після відхилення micro кандидата | `micro/comparison.csv`, `asm/micro-wipes.txt` |
| AES/GCM, ChaCha, SHA | Використовувати поточний AWS-LC | **Структурний/runtime факт:** AES/PMULL/eor3, SHA256 HW та SIMD ChaCha вже виконуються; виграш нового Rust rewrite не виміряний | Shared backend; own unsafe заборонений; не дублювати crypto trust scope | `profiles/`, `asm/aes-gcm-8x.txt`, `asm/chacha-open.txt`, `asm/sha256-hw.txt`, `native/native-flags-report.md` |
| Copies / padded inner scan / PKI overhead | Ownership або parser зміни після профілювання | **Неперевірені гіпотези:** чисел для запропонованих змін немає | Immutable input/authentication/loan/error contracts; default records unpadded, rposition знаходить type за першу перевірку. Шукати останній nonzero, не останній valid type | `profiles/`, production `protected.rs`, `baseline/pki/summary.csv` |

Найменша підтверджена зміна — Drop-only u128 — вже внесена за дозволом користувача.
Для SIMD немає підстав створювати окремий unsafe accelerated crate зараз.
Direct pointer `vld1q_u8`/`vst1q_u8` — unsafe на MSRV, vst1q — звичайний
unaligned store, не volatile erasure. Натомість протестований NEON кандидат
використовує підтримувані bytemuck/zeroize safe wrappers і жодних own intrinsics/ASM.
Дизасемблер: u128 → `stp xzr,xzr`; NEON → `str q0`; block8 → вісім stp на цикл.
Це встановлює lowering; кількість інструкцій не доводить причину latency.
`as_chunks_mut` stable з 1.88; `core::simd`/`as_simd_mut` нестабільні навіть у
перевірених Rust 1.98.0 sources. Запуски робили compiler 1.98.1, не окремим 1.98.0.
Primary API source URLs та hashes: `intrinsics-source-provenance.json`.

Zero bytes не залежать від endianness; bytemuck вирішує alignment, head/tail
стираються byte-wise, chunk remainder не втрачається. Не використовували CRC,
FP rounding або переповнювальні arithmetic intrinsics: вони не є гарячими
операціями цього крейта. Не міняли алгоритми AEAD/nonce byte order/tags.

**Чесний baseline.** Frozen поточний production до Drop зміни:
`baseline/comparison.csv`, `baseline/run.json`. Шість fresh-process repeats,
100 samples, 256 records у batch, rotating client order. AES128/256, ChaCha,
X25519/P256/HRR і fragment64; bulk 64/1024/16384 B, handshake fresh/reused buffers,
повний lifecycle. Payload equality/black_box, AEAD/PKI реальні, однаковий rustls
server і strict PKI adapter для обох TLS clients; resumption/0-RTT вимкнені.
Release tests/build/profile виконані окремо від timed runs. Параметри, argv,
версії, source/binary/fixture/raw-data hashes збережені. CPU affinity/frequency/
scheduler lock недоступні; враховувати шум і дивитися paired ratios + native control.

AES128/X25519 frozen pair, µs per record/operation:

| Операція | TLSed | rustls strict |
|---|---:|---:|
| RX 64 B / 1 KiB / 16 KiB | 0.192 / 0.432 / 4.193 | 0.215 / 0.462 / 5.036 |
| TX 64 B / 1 KiB / 16 KiB | 0.197 / 0.448 / 5.567 | 0.226 / 0.480 / 5.464 |
| Full handshake reused buffers | 117.719 | 120.198 |
| Full handshake fresh buffers | 120.041 | 120.104 |
| Lifecycle incl Drop | 136.667 | 122.500 |

У bulk повторно використовується вже established object; у handshake створюється
новий object із reused або fresh caller buffers. Handshake timer виключає Drop,
lifecycle включає. Окремо створено constructor-only diagnostic із НЕЗМІНЕНИМ
production engine: 32 constructors одним таймером, Vec capacity для client
collection поза таймером, ClientHello state/wire перевіряються після таймера,
Drop поза таймером. Включає harness Box/name/Arc work; fresh buffers allocation
включена лише для TLSed, rustls володіє власним storage всередині constructor.
TLSed constructor 7.328 µs/reused buffers або 8.605 µs/fresh; native controls
10.633 / 10.045 µs. Це не час цілого handshake. `construction/comparison.csv`.

PKI valid: strict adapter 26.090 µs, native webpki policy 25.260 µs (pooled p50).
Native PKI comparator НЕ має supplementary strict KeyUsage checks: це policy
margin, не чесний привід пропускати перевірки. Full TLS порівнює shared strict
policy. Negative signature і wrong-name результати перевіряються точно;
`baseline/pki/summary.csv`. Немає нового підтвердженого webpki SIMD кандидата.

**Профілі і actual native build.** Вісім окремих baseline `sample` windows:
AES RX/TX, ChaCha RX, lifecycle для обох participants, 2 s / 1 ms. Ціле
client/server pair; server AEAD теж потрапляє в профіль. Partial CSV — тільки
diagnostic, виключені з canonical timing. Mixed lifecycle attempt також явно
виключений (`profiles/run.json`). Inclusive sample counts не додавати; це
residency, не call counts чи точна частка часу операції.

У baseline `ClientConnection` drop glue +1736 (0x100009680) — decrement у byte
scratch loop; +364 (0x100009124) — decrement у вже aligned loan wipe.
Не приписувати всі 162 Drop samples побайтному стиранню. Graph не відображає
всі implicit Drop/native calls; доповнено AST, samples і matching-binary ASM.
Profiles підтверджують AES8x enc/dec, ChaCha combined open/seal і SHA256 HW для
обох implementations. SHA512 capability/dispatch є, sampled execution не доведено.

Версії: rustls 0.23.45 (2976d90fd1c2db6b518700dd101b714069cfcb17), webpki 0.103.15,
aws-lc-rs 1.18.2 / aws-lc-sys 0.46.0; AWS-LC fa9bc8d6f7cfb2cf849b247fb06bbbfc41ecc9d6.
Actual compiler logging у clone, 437 command records, native archive до/після
logging та обидва original archives byte-identical SHA
3ca5aff32f48eb44b7ea52288f786ed9a7c1c14ae50d22125473b1e551c4b8ab.
Це matching-byte reproduction, не спостереження історичного argv.
Основний C/ASM: O3/PIC/sections/C11, target arm64-apple-macosx, min macOS27.0;
BORINGSSL_IMPLEMENTATION/PREFIX, DARWIN_C_SOURCE, STDALIGN, BUILTIN_SWAP,
MY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION. Jitterentropy окремо effective O0;
не «виправляти» це глобальним O3. Explicit armv8.4-a+sha3 був compiler probe,
не прапорцем усього archive. Rust rustflags=[]; target-cpu=native не додавали.
Apple armcap + length>=256 dispatch selects8x на цьому M5. Деталі/повні argv:
`native/native-commands.json`, `native/native-flag-sets.json`,
`native/native-command-sourcehashes.json`, `native/logging-build.log`,
`native/source-provenance.json`. Два peers використовують однаковий AWS-LC.

**Коректність і Lean після перенесення.** cargo fmt і clippy --all-targets -D warnings
PASS; release workspace115 runtime tests +14 compile-fail doctests PASS;
production no_std wasm check PASS. Isolated Drop також115+14, block8 client26,
micro independent-range oracle PASS. Не подавати старі Miri/fuzz runs як нові
запуски поточного Drop. Попередні helper Miri/ASan results існують, новий core
Drop напряму покритий guarded test та existing fragmentation/malformed tests.

Astra subagent реально регенерував pinned Charon/Aeneas extraction:
Charon c8f15d7d / Aeneas557eff83. Generated Lean byte-identical; LLBC змінено лише
embedded handshake source та temporary dest path, не translated functions/types.
Main Lean33 jobs + linked1728 jobs PASS; 168 standard-foundation theorem audits
(147 model +21 linked), 4923 differential cases/10 operations, source/freshness
checks PASS. Ledger/CORRESPONDENCE narrowly updated. Логи:
`verification/results/reassembler-drop-{translation,main-lean,linked-lean,models,axioms}.log`.

Це НЕ новий linked proof Drop/bytemuck/volatile/compiler/hardware і НЕ доказ
глобальної CPU-оптимальності. `ChunkedZeroization.lean` моделює exact arbitrary
initial-state head/mid/tail clearing і conditional minimum fixed-width chunks;
linked ReassemblyProof стосується checked length arithmetic. Не «виправляти»
translation-manifest hashes вручну: whole handshake.rs hash потребує реального
pinned regenerate при кожній наступній зміні навіть Drop-only.

**Артефакти і відтворення.** `production-before.json` та `production-after.json`
в audit directory однакові — audit-only scope. `implementation-after.json`
фіксує окреме наступне перенесення трьох production files і новий тест.
`scope-check.json`: audit229560 timed batches = baseline68400 + Drop64800 +
block8 64800 + micro29160 + constructor2400; samples не включені.
Executable bytes локально збережені в ignored `target/cpu-audit/`, hash catalog
`binary-catalog.json`; не шукати exe у report directory.

Isolated workspace: `target/cpu-audit/workspace/`; там є додаткові diagnostic
filters та experiments, це НЕ production джерело. Baseline/Drop/block8/constructor
executables окремо збережені. Frozen source snapshots `*.rs.txt`, patches,
lock/manifests і provenance у audit directory. Primitive source/runner:
`verification/experiments/cpu-audit/`; не переносити whole experiment у workspace.
Не запускати builds/profiles/fuzz одночасно з timing.

Production confirmation після перенесення завершився: ще 64 800 timed batches,
шість paired repeats, три сценарії. `production-drop-u128/before-after.csv`
в audit directory; усі36 process runs завершилися успішно.

| Production lifecycle | Before / after medians, µs | Paired speedup / repeat range | Control-normalized | After/native time |
|---|---:|---:|---:|---:|
| AES128/X25519 | 133.240 / 115.292 | 1.130× / 1.063–1.218× | 1.135× | 1.006× |
| ChaCha/X25519 | 138.417 / 122.875 | 1.127× / 1.114–1.146× | 1.138× | 1.005× |
| AES128/fragment64 | 136.104 / 122.448 | 1.112× / 1.072–1.135× | 1.113× | 1.004× |

Це medians of paired ratios; ділити дві pooled medians і називати це paired
speedup некоректно. Production bulk16K TX paired1.001×, RX0.990× (RX repeat
0.903–1.017×, normalized0.986×): додатковий bulk виграш не підтверджений;
невеликий зсув throughput потребує focused follow-up на тихіших/інших CPU.
Не замовчувати цей результат і не заявляти доведену відсутність усіх регресій.
Разом audit+production confirmation294360 timed batches. Models/builds/profiles
не запускалися паралельно із production timing.

Для контрольного повтору (новий output directory, root cwd):

```sh
python3 crates/tls-bench/compare_versions.py --before target/cpu-audit/client_compare_production_baseline --after target/release/client_compare --output verification/results/NEW-RUN --repeats 6 --samples 100 --bulk-records 256
```

**Наступна робота.** Поточна Drop-зміна, перевірки й confirmation завершені.
Далі лише за пріоритетом користувача: x86-64 + Linux/Windows measurements;
профілі довгих/пошкоджених/padded inputs перед новими optimizations; code-level
rustls/webpki improvement proposals із контрольованими experiments. Незавершені
повні v1 gates — server/mTLS/OpenSSL/adapters, security review. Не обіцяти
«TLSed всюди швидший» або «formally verified whole TLS» за цими даними.

Subagents `/root/lean_proofs` (Astra/high, verification) і
`/root/research_baseline` (Sol/medium, native/source audit) завершили й idle.
`/root/rust_core` старий errored agent не використовувався у цьому аудиті.
Усі інструментальні sessions завершені, активних subagent jobs чи background
build/test/profile/benchmark немає. Root додатково зберіг final artifact hashes
і scope checks. Жодних pending approvals немає.

Graph `tlsed-foundation` reindexed fast після змін: 5066 nodes / 9970 edges;
benchmark bins виключені fast-фільтром, там потрібен прямий source fallback.
Final raw/source/log hashes: `verification/results/2026-10-14-cpu-audit/evidence-sha256.json`.
