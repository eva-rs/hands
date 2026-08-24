# Changelog

## Не выпущено

- **(ломающее)** Протокол 2: добавлены фоновые exec-сессии — `ExecStart`/`ExecPoll`
  (long-poll)/`ExecInput`/`ExecKill` с реестром сессий в `Ops` (общий для local и remote).
  Клиент: `exec_start`/`exec_poll`/`exec_input`/`exec_kill`. `Psk` получил `PartialEq`/`Eq`.

## Ранее в этой ветке

- Руки переписаны с нуля. Транспорт — Noise `NNpsk0` (`snow`) с симметричным
  pre-shared ключом (`SecretString`, 32 байта через HKDF-SHA256): без ключа handshake
  не проходит. Бутстрап демона — на фреймворке eva (`App` + `Supervisor`). Единый API
  `Hands` для локального и удалённого режима; операции shell/файлы/поиск и потоковый
  перенос файлов (`copy`). Протокол версии 1.
