# Usuários, Grupos e Permissões no Linux

---

## Tabela de Usuários e Grupos no Linux

| Tipo                | Nome Exemplo                | UID   | GID   | Grupo Primário        | Pode Logar? | Descrição                                                                  |
| ------------------- | --------------------------- | ----- | ----- | --------------------- | ----------- | -------------------------------------------------------------------------- |
| Superusuário        | `root`                      | 0     | 0     | root                  | Sim         | Tem acesso total ao sistema. Ignora permissões.                            |
| Usuários de sistema | `daemon`, `bin`, `www-data` | 1–999 | 1–999 | próprio nome ou comum | Não         | Usados por processos ou serviços internos (ex: web server, banco de dados) |
| Usuários comuns     | `luiz`, `maria`             | 1000+ | 1000+ | nome do usuário       | Sim         | Criados para pessoas. Podem logar e rodar processos no sistema.            |
| Usuário `nobody`    | `nobody`                    | 65534 | 65534 | nogroup               | Não         | Restrito, usado como fallback ou isolamento extremo.                       |

---

## UIDs e GIDs

- **UID (User ID):** Identificador único de um usuário.
  - `0` é o **root** (superusuário)
  - `1–999`: usuários de **serviço ou sistema**
  - `1000+`: **usuários normais** (em sistemas Debian/Ubuntu)
- **GID (Group ID):** Identificador de grupos.
  - Funciona igual ao UID, mas para grupos

---

## Como funcionam os grupos no Linux?

- Um usuário **sempre pertence a um grupo primário**, criado junto com o usuário e geralmente com o mesmo nome.
- Pode pertencer a **grupos adicionais** para ter acesso compartilhado a arquivos, dispositivos e permissões específicas.
- As permissões de arquivos consideram:
  1. Se o usuário é o **dono** do arquivo (usuário)
  2. Se o usuário pertence ao **grupo** do arquivo
  3. Caso contrário, aplicam-se as permissões para **outros**

Exemplo:

- Usuário `luiz` tem grupo primário `luiz`
- Pode fazer parte do grupo extra `devs` para ter acesso a projetos compartilhados

---

## Permissões de Arquivos no Linux

### Significado das permissões `r`, `w`, `x`

| Letra | Nome    | Em arquivos                              | Em diretórios                                        |
| ----- | ------- | ---------------------------------------- | ---------------------------------------------------- |
| `r`   | read    | Pode ler o conteúdo do arquivo           | Pode listar os arquivos do diretório                 |
| `w`   | write   | Pode modificar/excluir o arquivo         | Pode criar, renomear e excluir arquivos no diretório |
| `x`   | execute | Pode executar o arquivo (script/binário) | Pode entrar no diretório e acessar seus arquivos     |

---

### Estrutura das permissões

Exemplo de saída de `ls -l`:

```bash
-rwxr-x---
```

Interpretação:

| Posição | Significado                                  |
| ------- | -------------------------------------------- |
| `-`     | Tipo de arquivo (`-` arquivo, `d` diretório) |
| `rwx`   | Permissões do dono do arquivo                |
| `r-x`   | Permissões do grupo do arquivo               |
| `---`   | Permissões para os outros usuários           |

Significado:

- Dono tem permissão para ler, escrever e executar
- Grupo pode ler e executar, mas não escrever
- Outros não têm permissão

---

### Como o Linux decide qual permissão usar?

1. Se o usuário for o **dono**, usa o bloco do **dono**.
2. Senão, se o usuário estiver no **grupo** do arquivo, usa o bloco do grupo.
3. Senão, usa o bloco de **outros**.

---

### Representação numérica (modo octal)

Cada permissão tem um valor numérico:

- `r` = 4
- `w` = 2
- `x` = 1

Exemplo:

```bash
chmod 750 script.sh
```

Significa:

- 7 = 4+2+1 → dono: ler, escrever e executar
- 5 = 4+0+1 → grupo: ler e executar
- 0 = 0+0+0 → outros: sem permissão

---

## Comandos úteis

| Ação                       | Comando                       |
| -------------------------- | ----------------------------- |
| Criar usuário              | `useradd -m luiz`             |
| Criar grupo                | `groupadd devs`               |
| Adicionar usuário a grupo  | `usermod -aG devs luiz`       |
| Ver grupos do usuário      | `groups luiz`                 |
| Ver UID, GID e grupos      | `id luiz`                     |
| Ver permissões de arquivos | `ls -l`                       |
| Mudar dono do arquivo      | `chown luiz:devs arquivo.txt` |
| Mudar permissões           | `chmod 750 script.sh`         |

---
