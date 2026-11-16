# Context-Guard — Roadmapa rozwoju `v4.5.2`–`v5.0.0` oraz wpis Architectural Freeze

**Status:** `ARCHITECTURAL FREEZE` — zatwierdzony kierunek; szczegóły implementacyjne podlegają testom kontraktowym  
**Data:** 16 listopada 2026  
**Punkt bazowy analizy:** `v4.5.1`, commit `54045e2f793893a895c8693f61c1ac63f0c7ed01` (`7/7` zielonych jobów Multi-OS CI według przekazanej weryfikacji)  
**Obsługiwane środowiska:** Claude Code, Cursor, OpenAI Codex, Google Antigravity  
**Przeznaczenie dokumentu:** tworzenie specyfikacji, planów TDD, issue i kryteriów akceptacji kolejnych wydań

> [!NOTE]
> **Kontekst stanu repozytorium w `v4.5.3`:** Punkt bazowy przeglądu zakotwiczono w `v4.5.1` (`54045e2`), a w `v4.5.3` domknięto całą deltę kontraktową Milestone A i Milestone B niniejszego Architectural Freeze (`INV-1`–`INV-7`). Wdrożono nieblokujące hashowanie `SHA-256` i `unlink` poza `_spool_lock`, monotoniczne przejście `preparing -> available -> evicting -> evicted` i stan `corrupt` bez recyklingu ID (z retry `PermissionError`/`EBUSY` na Windows), kody błędów `format_error` / `unexpectedly_missing` / `spool_corrupt`, limit `max_spool_entry_bytes` z walidacją UTF-8 przed spoolowaniem, kontrolę tożsamości katalogów przez `os.path.samefile()` oraz `--workspace-root` w CLI/MCP, a także pełny `ContextReceiptV1` z `turn_correlation`, deduplikacją `event_id` i metrykami `summarize_spool_lifecycle`, otwierając bramkę do prac nad `v4.6.0`.

---

## Część I — Przegląd architektoniczny i decyzja Architectural Freeze

Roadmapa zasługuje na ocenę **9,5/10** i nadaje się do zamrożenia architektonicznego (*Architectural Freeze*) po wprowadzeniu pięciu punktowych korekt w granicach kontraktów `v4.5.2`–`v4.7.0`. Zakotwiczenie planu w realnym stanie `v4.5.1` (`54045e2`, komplet `7/7` zielonych jobów Multi-OS CI, istniejący spool `slice`/`grep`/`list`/`gc` oraz Outcomes v4) uchroniło projekt przed efektem drugiego systemu — zamiast przepisywać działające fundamenty, dokument najpierw uszczelnia integralność i izolację dostępu, a dopiero potem buduje warstwę pomiarową i adaptacyjną.

### Co stanowi najmocniejszy fundament dokumentu

* **Brak efektu drugiego systemu:** Pozostawienie Policy API v1, Read Ledgera oraz manifestu JSON + lock do czasu benchmarków w `v4.9.0` chroni stabilność 7 jobów Multi-OS CI.
* **Właściwa sekwencja ryzyka:** Uszczelnienie integralności spoola i izolacji workspace w `v4.5.2` wyprzedza pomiary A/B (`v4.7.0`) oraz automatyzację decyzji (`v4.8.0`).
* **Równoległość prac po stabilizacji:** Niezależność `v4.6.0` (Advisor) od `v4.7.0` (Offline Replay) pozwala szybko dostarczyć widoczną funkcję CLI bez wstrzymywania prac nad ewaluacją.
* **Dyscyplina wydawnicza:** Trzy niezależne bramki (Contract, Reliability, Evidence) oraz warunkowa aktywacja Governora wiążą rozwój wtyczki z twardymi pomiarami.

### Pięć korekt kontraktowych przed zamrożeniem architektury

#### 1. Walidacja UTF-8 przy odczycie a fałszywy błąd integralności (`v4.5.2` A.4)

Wymuszenie ścisłego dekodowania UTF-8 (bez `errors="replace"`) dopiero podczas operacji `slice` i `grep` ze zwrotem `integrity_mismatch` łamie definicję ukończenia `v4.5.2` na rzeczywistych wyjściach narzędzi CLI. Logi systemowe na Windows (`CP1250`/`CP852`), zrzuty bajtowe w asercjach `pytest` czy `git diff` na plikach o mieszanym kodowaniu potrafią zawierać sekwencje niebędące poprawnym UTF-8. Jeżeli ścieżka zapisu przyjmie taki bufor, policzy poprawny `content_sha256` i odeśle skrót do agenta, a dopiero `slice` zablokuje odczyt błędem `integrity_mismatch`, wtyczka sama odetnie agenta od nieuszkodzonych danych i w `v4.8.0` fałszywie otworzy bezpiecznik. Poprawność UTF-8 trzeba weryfikować **przed podmianą wyniku przy zapisie** (brak poprawnego UTF-8 kieruje wywołanie na natychmiastowy passthrough albo oznacza zasób w manifeście jako binarny), rezerwując `integrity_mismatch` wyłącznie dla rozbieżności `total_bytes` lub `content_sha256`.

#### 2. Domyślne rozszczepienie zakresu `v4.5.2` oraz higiena blokady manifestu (`v4.5.2` A–E)

Zapisana w sekcji 5 reguła awaryjnego oddzielenia poprawek P0 od `ContextReceiptV1` powinna stać się planem podstawowym. Punkty A, B i C (weryfikacja `SHA-256`, tombstone’y przy współbieżnym GC oraz izolacja `workspace_id` w serwerze MCP) zamykają luki bezpieczeństwa i spójności danych, natomiast punkty D i E (nowy dziennik `ContextReceiptV1` oraz zmiana klasyfikacji regretu w Outcomes v4) to rozbudowa telemetrii, która zmienia semantykę raportów i zasługuje na osobne `v4.5.3`. Dodatkowo przy pozostawieniu backendu JSON + lock specyfikacja `v4.5.2` musi zabraniać trzymania blokady pliku manifestu w trakcie liczenia `SHA-256` na pliku payloadu oraz definiować górny pułap `max_spool_entry_bytes`, aby pojedynczy kilkusetmegabajtowy zrzut logów nie degradował latencji każdego wywołania `slice`.

#### 3. Kanonizacja `workspace_id` między hookiem a serwerem MCP na Multi-OS (`v4.5.2` C)

Oparcie domyślnej izolacji o kanoniczny katalog projektu to właściwa granica bezpieczeństwa, ale na macOS, Linuksie i Windows krótkotrwały proces hooka oraz długowieczny serwer MCP w Cursorze łatwo wyliczą różny identyfikator dla tego samego repozytorium. Dowiązania symboliczne na macOS (`/var` kontra `/private/var`), wielkość liter dysku na Windows (`C:\Repo` kontra `c:\repo`) oraz różnica między protokołem MCP `roots/list` a statyczną konfiguracją `.cursor/mcp.json` sprawią, że `slice` i `grep` odrzucą uprawnienia do własnych zasobów sesji. Kontrakt `v4.5.2` powinien narzucać jedną współdzieloną funkcję kanonizacji (`realpath` połączony z normalizacją wielkości liter na systemach plików niewrażliwych na wielkość znaków) oraz test krzyżowy zapisu przez hook i odczytu przez MCP na wszystkich platformach CI.

#### 4. Pasywna kontra aktywna inwentaryzacja schematów MCP (`v4.6.0`)

Lokalne pliki konfiguracyjne klientów zawierają komendy uruchomieniowe serwerów MCP, lecz nie zawierają samych schematów JSON narzędzi — te powstają dynamicznie po wywołaniu `tools/list`. Gdyby `cg budget --mcp` domyślnie uruchamiał skonfigurowane serwery MCP w celu pobrania ich schematów, naruszyłby zasadę braku efektów ubocznych (serwery mogą wymagać aktywnych tokenów autoryzacji, otwierać połączenia sieciowe lub zawieszać CLI). W `v4.6.0` tryb domyślny powinien analizować wyłącznie pasywne źródła (transkrypty sesji, lokalny cache definicji harnessu i pliki instrukcji, oznaczając brakujące schematy jako `unavailable`), natomiast aktywne odpytanie serwerów przez `tools/list` warto wydzielić za jawną flagą `--probe` ze sztywnym limitem czasu.

#### 5. Jedno źródło prawdy dla Outcomes v4 i wczesny zapis klucza capability (`v4.5.2`–`v4.7.0`)

Ponieważ w `v4.5.1` działa już moduł Outcomes v4, dołożenie obok niego `ContextReceiptV1` rodzi ryzyko utrzymywania dwóch niezależnych potoków zdarzeń, które zaczną rozjeżdżać się w `v4.7.0`. W architekturze należy jawnie wskazać, że `ContextReceiptV1` jest docelowo surowym rejestrem zdarzeń niskiego poziomu, a zagregowane wskaźniki Outcomes mogą być z niego deterministycznie wyliczane po spełnieniu wymagań trwałości i deduplikacji. Równocześnie minimalny odcisk `CapabilityAttestationKey` (identyfikator harnessu, build, wersja adaptera i skrót konfiguracji hooków) powinien być dopisywany do artefaktów pomiarowych już w `v4.7.0` Evidence Engine, aby zebrane przebiegi A/B miały komplet metadanych wymaganych później przez reguły Governora w `v4.8.0`.

| Wydanie | Obszar w dokumencie | Rekomendowana korekta | Cel zmiany |
| :--- | :--- | :--- | :--- |
| `v4.5.2` | Walidacja UTF-8 w `slice` i `grep` | Weryfikować UTF-8 przy zapisie spoola | Brak fałszywego `integrity_mismatch` |
| `v4.5.2` | Zakres wydania i blokada JSON | Wydzielić Receipt do `v4.5.3`, hashować poza lockiem | Szybki fix P0 i niskie p99 |
| `v4.5.2` | Izolacja `workspace_id` w MCP | Wspólna kanonizacja ścieżek i testy Multi-OS | Spójna autoryzacja hook–MCP |
| `v4.6.0` | Inwentaryzacja `cg budget --mcp` | Pasywny odczyt domyślnie, aktywne `--probe` opt-in | Brak efektów ubocznych przy audycie |
| `v4.7.0` | Artefakty Evidence Engine | Zapisywać `CapabilityAttestationKey` w raportach | Gotowy wsad pod reguły `v4.8.0` |

Po dopisaniu do dokumentu walidacji UTF-8 przed zapisem spoola, kanonizacji ścieżek `workspace_id` pod Multi-OS oraz pasywnego domyślnego trybu `cg budget --mcp`, roadmapę oznaczono jako **Frozen** z doprecyzowaniem dwóch poniższych zastrzeżeń architektonicznych.

### Decyzja: akceptuję korekty, z dwoma zastrzeżeniami architektonicznymi

Roadmapę Context-Guard od `v4.5.2` do `v5.0.0` uznano za gotową do **Architectural Freeze**. Wszystkie pięć proponowanych korekt ma uzasadnienie techniczne i poprawia wykonalność planu; szczególnie trafne jest wydzielenie `v4.5.2` jako szybkiego wydania naprawczego, bez uzależniania poprawek integralności od budowy nowej telemetrii.

Dwa zastrzeżenia doprecyzowane w kontraktach technicznych:

1. `ContextReceiptV1` nie może być jedynym źródłem prawdy, jeśli jest zapisywany jako best-effort JSONL. Najpierw potrzebny jest trwały, deduplikowalny rejestr zdarzeń albo formalna migracja istniejącego Outcomes v4.
2. Izolacja workspace musi mieć wiarygodne źródło tożsamości projektu. Sama współdzielona funkcja `realpath()` nie rozwiązuje problemu globalnego serwera MCP, który nie wie, z którego projektu pochodzi wywołanie.

#### Zaktualizowana kolejność wydań

| Wersja | Ostateczny zakres | Kryterium zamknięcia |
| :--- | :--- | :--- |
| `4.5.2` | Integralność recovery, tombstone, izolacja workspace, limity payloadów | Bezpieczne odczyty, GC i Multi-OS |
| `4.5.3` | `ContextReceiptV1`, korekta regretu, korelacja recovery | Spójna semantyka zdarzeń bez regresji Outcomes v4 |
| `4.6.0` | Preamble & MCP Advisor: pasywny audyt, opcjonalne `--probe` | Zero efektów ubocznych w trybie domyślnym |
| `4.7.0` | Evidence Engine: offline replay i stopniowe live A/B | Wiarygodne wyniki i pełne metadane środowiska |
| `4.8.0` | Capability Negotiation i konserwatywny Governor | Brak aktywacji na niezweryfikowanych możliwościach |
| `4.9.0` | Explainability, hardening, opcjonalny eksport OTel | Odtwarzalne decyzje i odporność operacyjna |
| `5.0.0` | Stabilizacja Policy API, schematów i kompatybilności | Stabilny publiczny kontrakt |

#### 1. `v4.5.2` — dokładny kontrakt techniczny

* **UTF-8: walidacja przed spoolowaniem:** Jeżeli `slice` i `grep` są operacjami tekstowymi, nie powinny przyjmować zasobu, którego nie potrafią później poprawnie odtworzyć. Pełna obsługa zasobów binarnych nie wchodzi do `4.5.2`, ponieważ wymagałaby odrębnego interfejsu odzyskiwania zamiast istniejących operacji tekstowych. Jeśli harness przekazuje do hooka już zdekodowany string, Context-Guard nie ma możliwości odtworzenia pierwotnego strumienia bajtów — gwarancja integralności obejmuje dokładnie tę reprezentację, którą faktycznie otrzymał.

| Sytuacja | Zachowanie |
| :--- | :--- |
| Źródłowe bajty nie są poprawnym UTF-8 | Passthrough, bez spoolowania |
| Rozmiar przekracza `max_spool_entry_bytes` | Passthrough |
| `SHA-256` lub długość nie zgadzają się podczas recovery | `integrity_mismatch` |
| `SHA-256` jest poprawny, ale zapisany tekst nie spełnia kontraktu kodowania | `decode_error` lub `format_error` |
| Upstream dostarczył już tekst z podstawionymi znakami | Nie deklarować integralności oryginalnych bajtów upstream |

* **Hashowanie poza lockiem, bez wyścigu z GC:**
  1. Pod krótką blokadą odczytać stan manifestu, wersję zasobu, oczekiwany hash i długość oraz otworzyć uchwyt do payloadu.
  2. Zwolnić blokadę. Odczytać bajty z otwartego uchwytu i sprawdzić długość, `SHA-256` oraz kodowanie.
  3. Zwrócić wyłącznie zweryfikowaną zawartość. GC musi respektować rozpoczęte odczyty lub bezpiecznie odroczyć fizyczne usunięcie pliku (na Windows otwarty uchwyt może uniemożliwić `unlink()`, więc GC pozostawia operację do ponowienia; na POSIX otwarty deskryptor nadal wskazuje dane po usunięciu nazwy pliku). Do tego dochodzi `max_spool_entry_bytes` przed rozpoczęciem spoolowania.

#### 2. Workspace isolation — jeden dodatkowy warunek krytyczny

Wspólna kanonizacja po obu stronach jest konieczna: `realpath()` rozwiązuje dowiązania symboliczne, a `normcase()` normalizuje wielkość liter na Windows. Na macOS `normcase()` nie zmienia wielkości liter mimo potencjalnie case-insensitive systemu plików, dlatego przy porównaniach istniejących katalogów należy wykorzystywać rzeczywistą tożsamość obiektu przez `os.path.samefile()`. Ponieważ w nowszych wersjach protokołu MCP (`2026-07-28+`) `roots/list` jest oznaczane jako deprecated i same `roots` stanowią informację o projekcie, a nie mechanizm kontroli dostępu, obowiązuje następujący model:

| Scenariusz | Decyzja |
| :--- | :--- |
| Serwer MCP uruchomiony z wiarygodnym, przypiętym workspace | Dostęp tylko do jego zasobów |
| Multi-root z jednoznacznie ustalonym zakresem konkretnego wywołania | Dostęp do odpowiedniego workspace |
| Globalny serwer bez informacji o pochodzeniu wywołania | Odmowa zamiast fallbacku do `global` |
| Tryb `global` świadomie wybrany przez użytkownika | Dostęp zgodny z konfiguracją |

#### 3. `v4.5.3` — `ContextReceipt` a istniejący Outcomes v4

Docelowa zasada „surowe zdarzenia są źródłem prawdy, Outcomes są widokiem zagregowanym” wymaga etapowej migracji i nie może opierać się na opcjonalnym JSONL jako autorytatywnym rejestrze:

| Etap | Źródło prawdy | Rola Context Receipt |
| :--- | :--- | :--- |
| `v4.5.2` | Obecny manifest i Outcomes v4 | Bez nowego kontraktu |
| `v4.5.3` | Obecne trwałe rejestry, wspólna semantyka `event_id` | Ujednolicony format zdarzeń i diagnostyczny zapis |
| `v4.7.0` | Trwały, deduplikowalny rejestr zdarzeń albo mechanizm równoważny | Podstawa deterministycznej agregacji Outcomes i offline replay |

W `4.5.3` zdarzenie jest tworzone logicznie tylko raz, a następnie przekazywane do rejestrów (bez niezależnej interpretacji tej samej interwencji w dwóch modułach). Awaria zapisu pomocniczego JSONL nie może powodować utraty danych recovery, a przy rekonstrukcji Outcomes należy raportować kompletność danych.

#### 4. `v4.6` i `v4.7` — dwie korekty zamrożone od razu

* **Preamble Advisor (pasywny domyślnie):** `cg budget --mcp` analizuje konfiguracje, znane schematy, transkrypty i lokalne dane bez uruchamiania procesów zewnętrznych; `--probe` jest oddzielną, jawną diagnostyką z możliwymi efektami ubocznymi.
* **Evidence Engine (identyfikowalność środowiska):** Eksperymenty live i offline zapisują co najmniej `harness_id`, `harness_build_id`, `adapter_version`, `hook_config_fingerprint`, `context_guard_version`, `model_id` oraz użyte capabilities i poziom ich dowodu; sama obecność `CapabilityAttestationKey` nie oznacza `runtime_verified`.

#### Ostateczny status Architectural Freeze

| Decyzja | Status |
| :--- | :--- |
| Podział `v4.5.2` / `v4.5.3` | Zatwierdzony |
| UTF-8 przed spoolowaniem | Zatwierdzony |
| `max_spool_entry_bytes` + hash poza lockiem | Zatwierdzony z wymaganiem stabilnego uchwytu |
| Wspólna kanonizacja workspace | Zatwierdzona; wymaga wiarygodnej identyfikacji wywołującego MCP |
| Pasywny `cg budget --mcp` | Zatwierdzony |
| Capability metadata w Evidence Engine | Zatwierdzone |
| `ContextReceipt` jako przyszłe źródło agregacji Outcomes | Zatwierdzone kierunkowo; migracja wymaga trwałego rejestru |

Dokument umieszczono w korzeniu repozytorium jako [ROADMAP.md](ROADMAP.md) (ze względu na regułę higieny wydania blokującą katalog `docs/`). Dalsza praca opiera się na poniższym zamrożonym kontrakcie wydawniczym.

---

## Część II — Ostateczna roadmapa rozwoju `v4.5.2`–`v5.0.0`

### 1. Kierunek produktu

Context-Guard ewoluuje z zestawu optymalizacji tokenów do lokalnej warstwy **Trust + Evidence + Adaptation**, odpowiedzialnej za bezpieczne przekształcanie kontekstu agentów, odzyskiwanie informacji, uczciwy pomiar efektów oraz dobór strategii w granicach możliwości konkretnego harnessu.

* **Trust:** transformacja nie może niejawnie odebrać agentowi dostępu do potrzebnych danych w zadeklarowanym okresie retencji. Integralność, izolacja i zachowanie w przypadku awarii mają pierwszeństwo przed oszczędnością.
* **Evidence:** oddzielamy zmniejszenie rozmiaru outputu, rzeczywisty billing, efekt cache, dodatkowe tury i ukończenie zadania. Korelacja nie jest dowodem przyczynowym.
* **Adaptation:** aktywacja optymalizacji jest deterministyczna, ograniczona zweryfikowanymi capabilities; twarde błędy prowadzą do bezpiecznego fallbacku.

**Nie wchodzą do strategii:** kolejna duża biblioteka filtrów CLI, własny kompresor ML, obowiązkowa usługa cloud, domyślna zdalna telemetria, nowy system pamięci agentów ani rozbudowany SDK dla nieistniejących jeszcze autorów rozszerzeń.

### 2. Stan bazowy i ograniczenia

W `v4.5.1` istnieją już Policy API v1, Read Ledger, Outcomes v4, Reversible Output Spool (`slice` / `grep` / `list` / `gc`), integracje z harnessami, shadow mode i podstawy replay/benchmark. Nie budujemy tych modułów od nowa.

W każdej wersji obowiązują:

* **Correctness before compression:** brak bezpiecznej ścieżki odzyskania oznacza passthrough.
* **Local-first:** dane i polityki pozostają lokalne; pełne payloady nie trafiają domyślnie do telemetrii.
* **Harness-bounded claims:** gwarancja odnosi się wyłącznie do obserwowalnej granicy konkretnego klienta.
* **Backward compatibility:** chronimy Policy API v1, Read Ledger, istniejące instalacje i migracje.
* **Measured / estimated / unavailable:** brak danych nie oznacza zera oszczędności ani zera błędów.
* **Release gates:** Contract, Reliability, Evidence i pełne Multi-OS CI; nie publikujemy tagu przed ich przejściem.
* **Budżety repozytorium:** utrzymać wymagania Python 3.9+, limity LOC/topologii i istniejące repozytoryjne bramki; nową logikę spoola wydzielać do odpowiednich modułów, zamiast rozbudowywać pliki hooków.

### 3. Zamrożona sekwencja wydań

| Wydanie | Główny cel | Co dostarcza | Warunek przejścia |
| :--- | :--- | :--- | :--- |
| `v4.5.2` | Spool Reliability | Integralność bajtowa, bezpieczne GC, tombstone, workspace isolation, limity payloadów | Siedem invariantów i pięć grup testów na Multi-OS |
| `v4.5.3` | ContextReceipt & Outcome Semantics | Receipt V1, korekta `suspected` regretu, korelacja recovery | Brak podwójnego liczenia i regresji Outcomes v4 |
| `v4.6.0` | Preamble & MCP Budget Advisor | Pasywny audyt, rekomendacje, opcjonalny `--probe` | Brak efektów ubocznych w trybie domyślnym |
| `v4.7.0` | Evidence Engine | Offline replay, kontrolowany live A/B, metryki kosztu i jakości | Odtwarzalna metodologia z jawną niepewnością |
| `v4.8.0` | Capability-Aware Governor | Runtime capability attestation, `active` / `shadow` / `passthrough`, circuit breaker | Brak decyzji wykraczających poza potwierdzone możliwości |
| `v4.9.0` | Explainability & Hardening | `cg explain`, retencja, diagnostyka, opcjonalny OTel export | Odporność operacyjna i audytowalność |
| `v5.0.0` | Stable Reliability Platform | Stabilne kontrakty, CLI i macierz kompatybilności | Bezpieczne migracje, udokumentowane gwarancje |

Nie zakładamy dat kalendarzowych. Kolejne wersje są zależne od bramek jakości, nie od terminarza.

### 4. `v4.5.2` — szczegółowy kontrakt wydania (P0/P1)

**Cel:** uszczelnić istniejący spool; bez zmian strukturalnych w Read Ledger i Outcomes v4. Nowy Context Receipt i reklasyfikacja regretu docelowo rozdzielone od poprawek P0.

#### 4.1. Zapis i odczyt danych

* Przy wejściu `str`: `.encode("utf-8", errors="strict")`; przy surowych bajtach: walidacja `.decode("utf-8", errors="strict")`. Samotne surogaty i niepoprawne kodowanie kierują na passthrough bez utworzenia zasobu.
* Sprawdzać limit konfiguracyjny `max_spool_entry_bytes` przed kosztowną transformacją. Przekroczenie limitu kieruje na passthrough. Domyślna wartość jest parametrem do ustalenia testami, nie obietnicą architektoniczną.
* Payload jest write-once dla unikalnego `spool_id`: zapis pliku tymczasowego, weryfikacja, `os.replace()` na tym samym filesystemie, następnie zatwierdzenie manifestu w stanie `available`.
* Skróconą odpowiedź wolno wyemitować dopiero po pozytywnym zatwierdzeniu payloadu i manifestu. Wcześniejsza awaria oznacza przekazanie oryginalnej odpowiedzi bez podmiany.
* `slice` / `grep` przed zwróceniem jakiegokolwiek fragmentu porównują pełny `total_bytes` i `content_sha256`, a następnie dekodują całość tekstu ściśle jako UTF-8. Cięcie następuje na granicach pełnych znaków lub linii; offsety bajtowe są półotwarte `[start, end)`.
* Błąd rozmiaru/hash: `integrity_mismatch`; poprawne bajty, ale niezgodny format/UTF-8 (stan nieosiągalny przy prawidłowym zapisie): `format_error`, nie fałszywy `integrity_mismatch`. Brak pliku przy `available`: `unexpectedly_missing`.
* `source_hash` dotyczy dokładnych bajtów otrzymanych przez Context-Guard, nie obiecuje, że upstream nie uciął odpowiedzi wcześniej.

#### 4.2. Blokady, GC i spójność

**Protokół odczytu:**

1. Pod krótkim `_spool_lock` pobrać stan i metadane, sprawdzić dostęp oraz otworzyć uchwyt do niezmiennego pliku.
2. Zwolnić blokadę; z otwartego uchwytu odczytać całe dane, porównać rozmiar, `SHA-256` i UTF-8.
3. Zwrócić wyłącznie zweryfikowane dane; bezpiecznie zamknąć uchwyt. Odczyt rozpoczęty przed zmianą stanu na `evicting` może dokończyć operację.

**Protokół GC:**

1. Pod `_spool_lock` atomowo zatwierdzić `evicting` z przyczyną `ttl_expired`, `max_entries_lru` albo `max_bytes_lru`.
2. Po zwolnieniu blokady wykonać `os.unlink()` poza sekcją krytyczną.
3. Po skutecznym usunięciu atomowo zatwierdzić `evicted` (tombstone). Przy `PermissionError` na Windows pozostawić `evicting` i ponowić później.
4. Następne odczyty widzące `evicting` lub `evicted` zwracają `evicted` z przyczyną, nie `unexpectedly_missing`.
5. Po awarii/restarcie GC domyka nieukończone eksmisje i sprząta osierocone payloady. Tombstone’y mają ograniczony liczbowo i czasowo rejestr; orientacyjnie `128` wpisów i `7–14` dni, parametry do walidacji w specyfikacji.

Nie wykonywać `SHA-256` ani `os.unlink()` pod `_spool_lock`. Poza sekcją krytyczną są też długotrwałe dekodowanie i formatowanie. Nie zakładać, że `os.replace()` samo w sobie zapewnia pełną trwałość po awarii zasilania; jeśli taką gwarancję deklarujemy, specyfikacja musi określić synchronizację pliku/katalogu.

**Stany:** `preparing` (wyłącznie wewnętrzny, nigdy nieudostępniany), `available`, `evicting`, `evicted`, `corrupt`. Przejścia zasobu po zatwierdzeniu `available` są monotoniczne; nigdy nie używać ponownie `spool_id`.

#### 4.3. Izolacja workspace i MCP

**Tryby:** `workspace` (domyślny), `session` (wymaga wiarygodnego identyfikatora), `global` (jawny opt-in).

* Hook zapisuje zasób z tożsamością wiarygodnie ustalonego korzenia workspace; nie wywodzi jej z argumentu dostarczonego przez model.
* Serwer MCP `workspace` uruchamia się z przypiętym `--workspace-root` / `--workspace`; katalog jest rozwiązywany podczas startu bez wywoływania `os.getcwd()`. Bez potwierdzonej tożsamości workspace operacje `slice`, `grep`, `list` odmawiają dostępu i nie mogą autoryzować się korzeniami przekazanymi w argumentach wywołania przez model.
* Przechowywać `workspace_id` i kanoniczny root. Weryfikować rzeczywistą tożsamość istniejących katalogów przez `os.path.samefile()`; nie polegać wyłącznie na identyczności napisów ścieżek.
* Testować dowiązania, Windows drive-letter casing, macOS case-insensitive, usunięte/przeniesione rooty i multi-root. W razie braku wiarygodnej identyfikacji stosować odmowę, nie fallback do `global`.
* To logiczna izolacja projektów tego samego użytkownika, nie sandbox przeciwko lokalnemu procesowi o tych samych uprawnieniach. Manifest z bezwzględnymi ścieżkami musi mieć ograniczone uprawnienia i nie być eksportowany domyślnie.

#### 4.4. Siedem niezmienników blokujących tag

* **INV-1 — Passthrough przed mutacją:** nie emitować skrótu przed walidacją rozmiaru/UTF-8 i zatwierdzeniem zasobu jako `available`.
* **INV-2 — Pełna weryfikacja:** każdy odzyskany fragment musi pochodzić z całości pliku zweryfikowanej długością, `SHA-256` i ścisłym UTF-8.
* **INV-3 — Krótka blokada:** hashowanie i fizyczny `unlink` nie odbywają się pod `_spool_lock`.
* **INV-4 — Monotoniczne stany:** `available` → `evicting` → `evicted` albo przejście do `corrupt`; brak powrotu do `available` i recyklingu identyfikatorów.
* **INV-5 — Eksmisja ≠ korupcja:** `unexpectedly_missing` wyłącznie dla manifestu `available`; dla eksmisji zwracamy jej przyczynę.
* **INV-6 — Fail-closed workspace:** brak potwierdzonego rootu lub odmienne `samefile()` oznacza odmowę, nigdy ukryty tryb globalny.
* **INV-7 — Nienaruszalne Outcomes v4:** brak strukturalnych zmian w Outcomes v4 i Read Ledger w `v4.5.2`.

#### 4.5. Macierz zachowań

| Manifest | Payload | `slice` / `grep` | Kolejny GC | Klasyfikacja |
| :--- | :--- | :--- | :--- | :--- |
| `available` | poprawny hash i rozmiar | zwróć dane | TTL/LRU według polityki | `OK` |
| `available` | błędny hash/rozmiar | `integrity_mismatch` | oznacz `corrupt` | `reliability failure` |
| `available` | brak | `unexpectedly_missing` | oznacz `corrupt` | `reliability failure` |
| `evicting` | istnieje lub zablokowany | `evicted` + `reason` | ponów `unlink` | utrata retencji, bez corruption |
| `evicted` | brak | `evicted` + `reason` | retencja tombstone | utrata retencji, bez corruption |
| `corrupt` | dowolny | odmowa recovery | kwarantanna/sprzątanie według polityki | `reliability failure` |

#### 4.6. Pięć grup testów blokujących wydanie

1. **Bajty i UTF-8:** bit flip, dodatkowy bajt, CP1250 niebędące UTF-8, samotny surogat, limit `max_spool_entry_bytes + 1`, wielobajtowe znaki i granice `[start,end)`. Niepoprawne dane wejściowe: passthrough; uszkodzenie zapisanych bajtów: odmowa recovery.
2. **Reader/GC race:** bariera po otwarciu uchwytu; równoległe `evicting`; czytelnik kończy, nowe odczyty odmawiają; wariant POSIX oraz Windows `PermissionError`, retry po zamknięciu uchwytu.
3. **Crash i błędy zapisu:** `ENOSPC`, brak uprawnień i awaria manifestu wymuszają oryginalny wynik; restart po `evicting` domyka eksmisję i nie tworzy fałszywej korupcji.
4. **MCP/workspace Multi-OS:** projekt A nie czyta B przez `slice`/`grep`/`list`; brak identyfikatora workspace fail-closed; symlinki, różna pisownia ścieżki, multi-root i usunięty root.
5. **Hot-path contention:** sztucznie wolny SHA na dużym payloadzie nie zatrzymuje `list()` ani małego recovery na blokadzie; p95/p99 mierzone, próg testowy oparty na pomiarach CI, nie arbitralnej obietnicy czasu.

**Release gate `v4.5.2`:** `INV-1`–`INV-7`, wszystkie pięć grup testów, pełna macierz Multi-OS, brak regresji instalacji/deinstalacji. Nie łączyć tego wydania z przeprojektowaniem telemetryki.

### 5. `v4.5.3` — `ContextReceiptV1` i semantyka Outcomes

**Cel:** jeden kontrakt zdarzeń bez wymuszania migracji wszystkich dotychczasowych rejestrów.

* `ContextReceiptV1`: `schema_version`, `event_id`, `event_type`, `parent_event_id`, `session_id`, `tool_call_id`, `spool_id`, opcjonalne `turn_key` i `turn_correlation`, `ts_ms`, `hook_duration_ms`, `harness`, `intervention`, `mode`, `status`, `source_hash`, rozmiary, odzyskane przedziały `[start,end)` oraz `delivery_evidence` i `upstream_truncation`.
* `turn_correlation` przyjmuje co najmniej `harness_native`, `transcript_derived`, `unobserved`. Nie wyliczać `recovery_model_turns` jako wartości zmierzonej, gdy korelacja jest nieobserwowalna.
* Rozróżnić `replacement_emitted` od `delivery_verified`. Samo wywołanie `slice` / `grep` potwierdza użycie identyfikatora, nie dostarczenie pierwotnej podmiany modelowi.
* `repeat_after_spool`, `verbose_override`, `reread_trimmed_range` otrzymują `regret=suspected` z `evidence=observed`. Samo celowane recovery nie jest regretem; awaria integralności należy do `reliability_failure`.
* Metryki cyklu życia zasobu: `recovery_calls`, `recovery_model_turns` (gdy obserwowalne), `unique_recovered_bytes`, `total_recovered_bytes`, `recovery_amplification`, osobno koszt i awarie. Wielokrotne recovery sugeruje fragmentację, nie automatyczną winę optymalizacji.
* **Wersja przejściowa:** Outcomes v4 pozostaje trwałym źródłem operacyjnych agregatów; diagnostyczne, rotowane JSONL nie staje się automatycznie autorytatywnym event logiem. Jeden logiczny event jest tworzony raz i otrzymuje stabilny identyfikator; downstream deduplikuje. Braki w receipcie oznaczamy jako `incomplete`, nie jako zero.
* Dopiero gdy istnieje kompletny, trwały i deduplikowalny rejestr wraz z migracją, można wyprowadzać Outcomes deterministycznie wyłącznie ze zdarzeń. Nie wymuszać tej migracji w `v4.5.3`.

**Release gate:** deterministyczne testy deduplikacji i korelacji, brak double count, kompatybilność historycznych Outcomes, prawidłowe klasyfikatory i brak obowiązkowego zapisu surowych promptów.

### 6. `v4.6.0` — Preamble & MCP Budget Advisor

**Cel:** bezpieczna funkcja widoczna dla użytkownika, działająca domyślnie tylko do odczytu.

* Komendy docelowe: `cg budget --preamble`, `cg budget --mcp`, `cg budget --recommendations`.
* Źródła domyślne: konfiguracje, lokalne instrukcje, transkrypty i istniejące cache definicji schematów; nie uruchamiać serwerów MCP i nie wykonywać `tools/list` w zwykłym `cg budget`.
* Brakujące schematy i liczniki cache raportować `unavailable`. Szacunki tokenów i kosztów wyraźnie oznaczać `estimated`.
* `--probe` stanowi osobny, jawny tryb, z timeoutem, limitami zasobów, identyfikacją badanych serwerów i ostrzeżeniem, że nawet `tools/list` może uruchomić proces lub połączenie sieciowe.
* Analiza nakładania się schematów i narzędzi; ostrożne rekomendacje profili na start sesji, bez automatycznej zmiany zestawu MCP i bez deklarowanych „gwarantowanych oszczędności”.

**Release gate:** domyślny audyt nie wywołuje zewnętrznych procesów ani sieci i niczego nie modyfikuje; dane `measured`/`estimated`/`unavailable` są rozdzielone.

### 7. `v4.7.0` — Evidence Engine

**Cel:** ustalić koszt i wpływ na jakość pełnego zadania, a nie wyłącznie procent zredukowanych tokenów.

* **Offline Replay:** deterministyczna kontrola transformacji, integralności, latencji i kontraktów z rekordów referencyjnych; nie udawać, że replikuje trajektorię modelu.
* **Small Live Pilot:** orientacyjnie `6 zadań × 2 konfiguracje × 3 powtórzenia = 36 przebiegów`; szybka bramka wykrywania oczywistych regresji, nie dowód przewagi statystycznej.
* **Release Evaluation:** orientacyjnie `12–15 zadań × 3 konfiguracje × 2 powtórzenia = 72–90 przebiegów/harness`; baseline, Context-Guard, Context-Guard + RTK. Rozszerzać próbę tylko według budżetu i niepewności.
* **Metryka główna:** `Cost per Passed Run` = całkowity koszt wszystkich przebiegów / liczba sukcesów, wraz z przypadkiem braku sukcesów jako `undefined`. Obok `Pass Rate`, koszt sparowany na wspólnych sukcesach (jawnie warunkowy), liczba tur, latencja, cache read/write/fresh input, TTL, fragmentacja recovery i potwierdzone `reliability_failures`.
* Nie wyłączać endogenicznych TTL cache misses i kosztów nieudanych prób z głównego wyniku A/B. Odróżniać zakłócenia zewnętrzne.
* Eksperymenty muszą mieć izolowane workspace, przypięte wersje CLI i modeli, te same limity, kryteria zaliczenia oraz oznaczoną niepewność.
* Każdy artefakt zapisuje: `harness_id`, `harness_build_id`, `adapter_version`, `hook_config_fingerprint`, `context_guard_version`, `model_id`, wymagane capabilities i poziomy ich dowodu. Sama obecność `CapabilityAttestationKey` nie dowodzi `runtime_verified`.
* Cursor CLI dopuszczać po testach zgodności wymaganych kontraktów; brak cache telemetry wyklucza precyzyjne rozliczenie cache, nie wszystkie porównania.

**Release gate:** odtwarzalne raporty, ujawnione niepowodzenia, brak nieuprawnionych twierdzeń przyczynowych, kompletność metadanych.

### 8. `v4.8.0` — Capability-Aware Adaptive Governor

**Cel:** deterministycznie wybierać `active`, `shadow` lub `passthrough` dla optymalizatorów.

* `CapabilityContractV1` rozróżnia `unsupported`, `provider_supported`, `harness_exposed`, `runtime_verified`.
* Atestacja wiąże `(harness_id, harness_build_id, adapter_version, hook_config_fingerprint, capability_id)` i dowód weryfikacji. Zmiana builda, adaptera, istotnej konfiguracji albo nieznany payload degraduje dostępne gwarancje.
* Nie wywodzić wsparcia harnessu z samego wsparcia API modelu. Dynamiczna modyfikacja listy narzędzi wymaga weryfikacji rzeczywistego klienta, nie tylko dostawcy API.
* Circuit breaker aktywuje się dla twardych błędów integralności i utraty gwarancji, nie dla samego `suspected_regret` czy chunk-thrashingu.
* Histereza: po potwierdzonej awarii ponowna aktywacja dopiero po testach lub decyzji operatora. Governor nigdy nie obniża ochrony security policy.

**Release gate:** parity tests z konfiguracją statyczną, replay decyzji, testy aktualizacji harnessów i fail-safe downgrade; aktywację domyślną uzależnić od wyników Evidence Engine.

### 9. `v4.9.0` — Explainability & Operational Hardening

**Cel:** użytkownik może wyjaśnić konkretną interwencję i zweryfikować dostępność danych.

* `cg explain <event-id>`; diagnostyka lifecycle `spool_id`, aktualnego stanu, przyczyn eksmisji i poziomu dowodu dostarczenia.
* Eksport kompatybilnych zdarzeń do OTel wyłącznie poza hot path (`cg export --otel`), bez obowiązkowej ciężkiej biblioteki w hookach.
* Testy zmian wersji harnessu, sesji wznawianych, retencji, awarii dysku, uprawnień i współbieżności.
* Porównać JSON+lock, SQLite WAL i segmentowane JSONL tylko jeśli pomiary wykażą ograniczenia istniejącego backendu. Żadnej automatycznej migracji Read Ledgera.

**Release gate:** wyjaśnialność bez wycieku surowych promptów, mierzone p50/p95/p99, odtwarzalne zachowanie i bezpieczne migracje.

### 10. `v5.0.0` — Stable Context Reliability Platform

**Cel:** stabilizacja publicznych kontraktów i ergonomii; nie dodawanie funkcji dla numeru wydania.

* Spójne CLI: `doctor`, `budget`, `explain`, `eval`.
* Stabilne Policy API i pozostałe kontrakty, wersjonowanie schematów, polityka deprecacji i zgodne migracje.
* Publiczna macierz możliwości i ograniczeń Claude Code, Cursor, Codex, Antigravity.
* Conformance suite adapterów i podstawowych policy packów; pełny SDK dopiero przy rzeczywistym popycie.
* Brak obowiązku tworzenia Policy API v2, jeśli v1 wystarcza.

**Release gate:** zielone CI, udokumentowane gwarancje, migracje i rollback, raport dowodów skuteczności wraz z ograniczeniami.

### 11. Kontrakty przekrojowe

| Kontrakt | Miejsce pierwszego użycia | Invariant |
| :--- | :--- | :--- |
| `SpoolLifecycleV1` | `v4.5.2` | Bez utraty danych w zadeklarowanym okresie; planowa eksmisja nie jest korupcją |
| `WorkspaceAccessV1` | `v4.5.2` | Wiarygodny root procesu MCP; brak niejawnego `global` access |
| `ContextReceiptV1` | `v4.5.3` | Korelacja i dowód; surowe dane poza ledgerem |
| `OutcomeSemanticsV1` | `v4.5.3` | `suspected ≠ confirmed`; brakująca telemetria `≠ zero` |
| `EvidenceContractV1` | `v4.7.0` | Pełny koszt prób na sukces; jawna niepewność |
| `CapabilityContractV1` | Metadane w `v4.7.0`; runtime w `v4.8.0` | Zmiana builda/adaptera unieważnia atestację |

### 12. Plan przekazania do implementacji (najbliższy krok)

* **Milestone A — spec-first, `v4.5.2` / domknięcie przed `v4.6.0`:**
  1. Zamrozić publiczne/operacyjne kody błędów, stany manifestu, zasady uprawnień i semantykę półotwartych zakresów.
  2. Dopisać pięć grup testów kontraktowych: encoding/hash, GC races, crash, workspace/MCP i contention.
  3. Wdrożyć zapis write-once, limit payloadu i fail-safe passthrough (z walidacją UTF-8 przed spoolowaniem).
  4. Wdrożyć weryfikowany odczyt z otwarciem uchwytu pod krótką blokadą, a obliczaniem SHA poza nią.
  5. Wdrożyć `evicting` → `evicted`, tombstone i restart reconciliation.
  6. Wdrożyć przypięcie korzenia workspace, wspólną kanonizację, `samefile()` i odmowę przy braku tożsamości.
  7. Uruchomić pełne Multi-OS CI, testy migracji/rollbacku i benchmark latencji; dopiero wtedy tag.
* **Milestone B — `v4.5.3`:** Context Receipt, korekta regretu, korelacja recovery, walidacja idempotencji i kompletności zdarzeń.
* **Milestone C — `v4.6.0` i dalej:** realizować zakresy wydań według tabeli w sekcji 3, bez ponownego otwierania strategii.

### Zasady kontroli zmian

Status **ARCHITECTURAL FREEZE** zamraża kolejność i zakres funkcjonalny wydań oraz invariants. Nie zamraża wartości progów, backendu czy szczegółów adapterów, jeżeli testy ujawnią realne ograniczenie.

Zmiana zamrożonego kontraktu wymaga:

1. Konkretnego nieprzechodzącego testu lub nowego dowodu.
2. Oceny zgodności wstecznej.
3. Aktualizacji [ROADMAP.md](ROADMAP.md).
4. Ponownego przejścia **Contract Gate**.

**Decyzja końcowa:** priorytetem na styku `v4.5.2`/`v4.5.3` jest pełne domknięcie niezmienników integralności, nieblokującego hashowania/GC i izolacji `samefile()` przed przejściem do prac nad `v4.6.0` (`Preamble & MCP Budget Advisor`).
