# iauhty-export

[English](README.md) | **Português (Brasil)**

[![CI](https://github.com/BOTecko/iauhty-export/actions/workflows/ci.yml/badge.svg)](https://github.com/BOTecko/iauhty-export/actions/workflows/ci.yml)

Recupera os segredos TOTP do Authy a partir de um backup criptografado do
iPhone feito pelo Finder no macOS e os exporta como um cofre Aegis protegido
por senha, que pode ser importado em qualquer autenticador compatível com
Aegis. Testado com o Proton Authenticator.

Roda localmente, só com a biblioteca padrão do Python. O backup nunca é modificado.

> Apague o export assim que a importação terminar: ele contém todos os seus segredos de 2FA.

## Requisitos

- macOS
- Python 3.12+ ([python.org](https://www.python.org/downloads/macos/))
- Um backup criptografado do iPhone, feito pelo Finder, com o Authy instalado, e a senha dele
- Acesso Total ao Disco para o terminal (Ajustes do Sistema ▸ Privacidade e Segurança)

## Uso

```bash
git clone https://github.com/BOTecko/iauhty-export.git && cd iauhty-export
```

```bash
python3 -m iauhty_export inspect --unlock
```

```bash
python3 -m iauhty_export extract
```

O `extract` pede a senha do backup e uma senha nova para o export, e grava
`~/IauhtyExport/iauhty-export.json` com um relatório ao lado. Importe o arquivo
no seu autenticador (Proton Authenticator: Settings ▸ Import ▸ Aegis), confira
os códigos e apague os dois arquivos.

| Comando | Descrição |
| --- | --- |
| `list` | Lista os backups locais. |
| `inspect [--unlock]` | Mostra detalhes do backup; com `--unlock`, confere os dados do Authy. |
| `extract [--output FILE] [--force]` | Recupera os tokens e grava o export criptografado. |
| `verify --file FILE` | Valida um cofre Aegis sem mostrar segredos. |

`--backup PATH` escolhe um backup específico; por padrão é usado o
criptografado mais recente.

## Como funciona

- O keybag do backup é desbloqueado com a senha do backup; o `Manifest.db`, as
  preferências do Authy e o keychain são decifrados em memória.
- O Authy guarda um registro por conta em `group.authy.128FD4.plist` e o
  segredo num item do keychain chamado `Google<id>App`. O Authy não guarda o
  algoritmo nem o período; são usados SHA1 e 30 s.
- O export segue o formato de cofre do Aegis: um slot de senha (scrypt) e as
  entradas cifradas com AES-256-GCM.

## Limitações

- Tokens nativos do Authy não são suportados.
- Itens do keychain presos ao aparelho original ("ThisDeviceOnly") não podem ser recuperados.
- Só macOS.

## Desenvolvimento

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam backups sintéticos e vetores públicos do NIST e dos RFCs. Veja o
[CONTRIBUTING.md](CONTRIBUTING.md) e o [SECURITY.md](SECURITY.md).

## Licença

[MIT](LICENSE). Não é afiliado à Twilio, Authy, Apple, Proton ou Aegis.
