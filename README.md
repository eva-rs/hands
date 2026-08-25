# eva-hands

Руки Евы — файловые и процессные операции на рабочей машине: запуск shell-команд,
чтение/запись/поиск в файлах, перенос файлов между клиентом и сервером. Один и тот же
API [`Hands`] в двух формах:

- **Библиотека** — `Hands::local(limits)` выполняет всё в процессе, без сети.
- **Сервер + клиент** — `Hands::remote(addr, &psk)` говорит с демоном по зашифрованному
  каналу. Ключ шифрования симметричный (`SecretString`); **без ключа handshake не
  проходит**, подключиться невозможно.

## Шифрование

Канал — Noise `NNpsk0` (`snow`): обе стороны шлют эфемерные ключи (forward secrecy), а
общий ключ подмешивается в самое начало handshake. 32-байтный PSK выводится из
`SecretString` через HKDF-SHA256. Своей криптографии нет — только `snow` и стандартный
KDF. Ключ должен быть высокоэнтропийным: `NNpsk0` со слабой парольной фразой уязвим к
офлайн-перебору по перехваченному handshake. Сгенерировать ключ:

```
eva-hands keygen
```

## Протокол

Кадр: `u32 header_len | u32 body_len | header (JSON) | body (сырые байты)`. Содержимое
файлов едет в теле, вне JSON. Каждый запрос несёт `id`; ответы приходят в любом порядке —
одно соединение мультиплексирует всё, медленный `exec` не блокирует чтение файла. Рабочий
каталог — поле запроса, не состояние сессии. Версия протокола объявляется в handshake
(`Hello`); несовпадение ловится сразу.

## Операции

`ping`, `stat`, `list`, `read` (со смещением/длиной), `write` (атомарно: temp + fsync +
rename), `write_at`, `fetch` (скачать URL прямо на машину — потоком, мимо провода),
`find` (потоковый поиск по байтам с лимитом), `mkdir`, `remove`, `rename`, `exec` (через
`sh -c`, с таймаутом, stdin и неинтерактивным окружением). Перенос файлов в любую
сторону — `hands::copy(from, .., to, ..)`, потоково окнами.

У `fetch` `path` с завершающим `/` означает каталог: имя листа машина берёт из
`Content-Disposition`, иначе из хвоста URL, и возвращает получившийся путь. Прокси —
поле запроса: своей сетевой политики у рук нет, её задаёт вызывающий.

## Лимиты

`Limits` (объявляются клиенту в handshake): `max_read`, `max_write`, `max_hits`,
`max_output`, `exec`, `exec_timeout_secs`, `exec_max_timeout_secs`, `fetch`, `roots`
(лексический забор путей; пусто = вся ФС — грубый забор, не песочница).

`Error::Unavailable` (руки недостижимы — можно пойти другим путём) строго отделён от
`Error::Failed` (честный результат операции машины).

## Запуск демона

Бутстрап на фреймворке [eva](https://git.desu.church/VienDesu/eva): `eva::cli::App` для
конфигурации и `eva::supervisor::Supervisor` для graceful-остановки.

```
eva-hands --config hands.yaml
```

Секция `hands` (плюс флаг `--config`; env перекрывает файлы, префикс `EVA_`, вложенность
через `__`):

```yaml
hands:
  listen: "0.0.0.0:2222"
  # key: сюда лучше не писать — передавать через окружение/секрет-файл
  exec: true
  roots: []
```

Ключ — из окружения, чтобы не лежать в конфиге:

```
EVA_HANDS__KEY=<base64-ключ> eva-hands --config hands.yaml
```

## NixOS

`flake.nix` собирает пакет, dev-shell и `nixosModules.default` (через `eva.lib.mkServiceFlake`).
Не-секретная часть — в `services.eva-hands.settings` (рендерится в world-readable store),
ключ — в `environmentFiles` (`EVA_HANDS__KEY=...`) или в секретном `--config` через
`extraConfigFiles`.

```nix
services.eva-hands = {
  enable = true;
  settings.hands = {
    listen = "0.0.0.0:2222";
    roots = [ "/srv" ];
  };
  environmentFiles = [ "/run/secrets/eva-hands.env" ];  # EVA_HANDS__KEY=...
};
```

## Сборка

```
nix develop        # тулчейн + cc
cargo test
```
