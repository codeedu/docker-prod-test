# 🐧 Docker e Linux Kernel: Modelo de Segurança e Isolamento

## 📦 **Arquitetura: Container → Docker Engine → Linux Kernel**

```
┌─────────────────────────────────────────────────────────┐
│                     CONTAINERS                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │   App A  │  │   App B  │  │   App C  │               │
│  └──────────┘  └──────────┘  └──────────┘               │  
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    DOCKER ENGINE                        │
│         (containerd, runc, docker daemon)               │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    LINUX KERNEL                         │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │   NAMESPACES    │  │     CGROUPS     │               │
│  └─────────────────┘  └─────────────────┘               │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │   CAPABILITIES  │  │  SECCOMP/LSM    │               │
│  └─────────────────┘  └─────────────────┘               │
└─────────────────────────────────────────────────────────┘
```

---

## 🔒 **1. NAMESPACES - Isolamento de Recursos**

### **O que fazem:** Criam visões isoladas dos recursos do sistema

| Namespace | Isola                       | Exemplo Prático                                                        |
| --------- | --------------------------- | ---------------------------------------------------------------------- |
| **PID**   | Processos                   | Container vê seu processo como PID 1, não enxerga processos do host    |
| **NET**   | Rede                        | Cada container tem sua própria interface de rede (eth0), portas, rotas |
| **MNT**   | Sistema de arquivos         | Container tem seu próprio root filesystem (/) isolado                  |
| **UTS**   | Hostname/Domain             | Container pode ter hostname próprio sem afetar o host                  |
| **IPC**   | Comunicação entre processos | Semáforos, filas de mensagens isoladas por container                   |
| **USER**  | Usuários e grupos           | Root no container pode ser mapeado para usuário não-root no host       |

---

## ⚙️ **2. CGROUPS - Limitação de Recursos**

### **O que fazem:** Controlam quanto de recursos cada container pode usar

| Recurso     | Controle            | Exemplo                                |
| ----------- | ------------------- | -------------------------------------- |
| **CPU**     | Limita uso de CPU   | `--cpus="1.5"` (máximo 1.5 CPUs)       |
| **Memória** | Limita RAM          | `--memory="512m"` (máximo 512MB)       |
| **I/O**     | Limita disco        | `--device-read-bps` (limita leitura)   |
| **PIDs**    | Número de processos | `--pids-limit=100` (máx 100 processos) |

---

## 🛡️ **3. SECURITY LAYERS - Camadas Adicionais**

### **Componentes de Segurança:**

| Componente           | Função                         | Como funciona                              |
| -------------------- | ------------------------------ | ------------------------------------------ |
| **Seccomp**          | Filtra syscalls                | Bloqueia chamadas perigosas do kernel      |
| **Capabilities**     | Reduz privilégios              | Remove poderes do root (ex: CAP_NET_ADMIN) |
| **AppArmor/SELinux** | MAC (Mandatory Access Control) | Políticas que restringem acesso a arquivos |
| **rootless mode**    | Containers sem root            | Docker roda sem privilégios de root        |

---

## 🔍 **Exemplo Prático: Como verificar isolamento**

```bash
# Ver namespaces de um container
docker run -d --name test nginx
docker inspect test | grep -i pid

# Comparar processos - Host vs Container
ps aux | grep nginx  # No host
docker exec test ps aux  # No container (vê apenas seus processos)

# Ver cgroups limitando recursos
docker run -d --memory="100m" --cpus="0.5" nginx
cat /sys/fs/cgroup/memory/docker/[container-id]/memory.limit_in_bytes
```

---

## 📊 **Fluxo de Criação de Container**

```
1. Docker CLI → Comando docker run
2. Docker Daemon → Processa requisição
3. containerd → Gerencia ciclo de vida
4. runc → Cria container usando kernel features:
   ├── Cria namespaces (isolamento)
   ├── Aplica cgroups (limites)
   ├── Configura seccomp (segurança)
   └── Define capabilities (privilégios)
5. Container → Processo isolado rodando
```

---

## 💡 **Resumo: Container = Processo Linux Isolado**

**Um container NÃO é uma VM**, é um **processo Linux** com:

- ✅ **Namespaces** → Isolamento (o que pode ver)
- ✅ **Cgroups** → Limitação (quanto pode usar)
- ✅ **Security layers** → Proteção (o que pode fazer)

Tudo isso é **nativo do Linux Kernel** - Docker apenas orquestra essas features de forma amigável!

## 🪓 **Exemplo de Ataques com cada ponto**

---

### 🔹 Namespaces (Isolamento)

> Namespaces são usados para isolar recursos do sistema entre containers. Mas, se mal configurados ou explorados, podem ser burlados.

#### 🔸 `PID` (Processos)

* **Ataque**: *Escape via processos visíveis do host*.
* **Exemplo**: Se o container compartilha o namespace de PID com o host (`--pid=host`), o processo no container pode ver e tentar sinalizar processos do host.
* **Consequência**: Pode matar processos críticos do host com `kill`, caso tenha permissão.

**✅ Uso seguro:**
```bash
# Isolamento padrão (recomendado)
docker run -d nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Compartilhar namespace PID com o host
docker run -d --pid=host nginx
```

**🛡️ Como se proteger:**
```bash
# 1. NUNCA use --pid=host em produção
# 2. Use políticas de PSP/Pod Security Standards no Kubernetes
# 3. Audite containers com compartilhamento de namespace
docker ps --format "table {{.Names}}\t{{.Command}}" | grep -E "(--pid=host)"
```

---

#### 🔸 `NET` (Rede)

* **Ataque**: *Packet sniffing ou spoofing de rede*.
* **Exemplo**: Se for usado `--net=host`, o container tem acesso à pilha de rede do host e pode escutar tráfego da rede, incluindo requisições locais.
* **Consequência**: Roubo de dados sensíveis como tokens JWT ou credenciais.

**✅ Uso seguro:**
```bash
# Rede isolada com port binding
docker run -d -p 8080:80 nginx

# Rede customizada para isolamento entre aplicações
docker network create app-network --driver bridge
docker run -d --network app-network --name api1 nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Compartilhar namespace de rede com o host
docker run -d --net=host nginx
```

**🛡️ Como se proteger:**
```bash
# 1. EVITE --net=host
# 2. Use redes customizadas com segmentação
# 3. Implemente políticas de rede (iptables/firewall)
# 4. Use TLS/mTLS para comunicação entre containers

# Verificar containers com rede host
docker ps --format "table {{.Names}}\t{{.HostConfig.NetworkMode}}" | grep host
```

---

#### 🔸 `MNT` (Sistema de arquivos)

* **Ataque**: *Montar `/proc` ou `/host` e acessar arquivos do host*.
* **Exemplo**: Containers com volume montado para `/` ou `/proc` podem acessar `/etc/shadow`, `/etc/passwd`, ou `docker.sock`.
* **Consequência**: Escalada para root ou controle total do Docker (e do host).

**✅ Uso seguro:**
```bash
# Volumes específicos com read-only quando possível
docker run -v /app/data:/data:ro nginx
  
# Volumes nomeados para persistência segura
docker volume create app-data
docker run -v app-data:/data nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Montar sistema de arquivos do host
docker run -v /:/host nginx

# Montar socket do Docker
docker run -v /var/run/docker.sock:/var/run/docker.sock nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Use volumes read-only quando possível
docker run -v /config:/config:ro nginx

# 2. Evite montar diretórios sensíveis
# 3. Use named volumes ao invés de bind mounts
docker volume create app-data
docker run -v app-data:/data nginx

# 4. Audite volumes perigosos
docker ps --format "json" | jq -r '.Mounts[] | select(.Source == "/" or .Source == "/var/run/docker.sock")'
```

---

#### 🔸 `UTS` (Hostname)

* **Ataque**: *Spoofing ou manipulação de hostname*.
* **Exemplo**: Se `--uts=host` for usado, pode haver interferência com serviços que confiam no nome da máquina (ex: logs, auditoria, DNS interno).
* **Consequência**: Confusão ou manipulação de sistemas de monitoramento.

**✅ Uso seguro:**
```bash
# Hostname customizado isolado
docker run -d --hostname myapp nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Compartilhar namespace UTS com o host
docker run -d --uts=host nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Mantenha UTS namespace isolado
# 2. Use hostnames descritivos para containers
# 3. Configure logging centralizado que inclua container ID
docker run -d --hostname prod-api-01 --log-driver=syslog nginx
```

---

#### 🔸 `IPC` (Comunicação entre processos)

* **Ataque**: *Interferência em memória compartilhada de outro container*.
* **Exemplo**: Containers compartilhando o namespace IPC (`--ipc=host`) podem ler ou interferir em segmentos de memória usados por outros containers.
* **Consequência**: Vazamento ou corrupção de dados entre containers.

**✅ Uso seguro:**
```bash
# IPC isolado (padrão)
docker run -d nginx

# Compartilhamento controlado apenas entre containers relacionados
docker run -d --name app1 nginx
docker run -d --name app2 --ipc=container:app1 nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Compartilhar IPC com o host
docker run -d --ipc=host nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Evite --ipc=host
# 2. Use IPC compartilhado apenas quando necessário
# 3. Prefira comunicação via rede (REST, gRPC) ao invés de IPC
# 4. Audite containers com IPC compartilhado
docker inspect $(docker ps -q) | jq -r '.[] | select(.HostConfig.IpcMode != "private") | .Name'
```

---

#### 🔸 `USER` (Usuários e Grupos)

* **Ataque**: *Privilégios excessivos por rodar como root*.
* **Exemplo**: Rodar containers como root (`user: 0`) pode permitir exploits locais, como modificar arquivos de sistema ou instalar backdoors.
* **Consequência**: Acesso root ao container ou ao host (se combinado com falhas no MNT ou volumes perigosos).

**✅ Uso seguro:**
```dockerfile
# Dockerfile com usuário não-root
FROM alpine
RUN addgroup -g 1001 -S appuser && adduser -S appuser -u 1001
USER appuser
COPY --chown=appuser:appuser . /app
```

```bash
# Executar container com usuário não-privilegiado
docker run -u 1001:1001 nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Executar como root (padrão em muitas imagens)
docker run nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Sempre defina USER no Dockerfile
# 2. Use user namespaces para remapear root
dockerd --userns-remap=default

# 3. Audite containers rodando como root
docker ps --quiet | xargs docker inspect | jq -r '.[] | select(.Config.User == "" or .Config.User == "root") | .Name'

# 4. Use políticas de segurança
docker run --security-opt=no-new-privileges nginx
```

---

### 🛡️ Segurança e Controle

#### 🔸 `Cgroups` (Limites de recursos)

* **Ataque**: *Denial of Service (DoS)* por consumo excessivo.
* **Exemplo**: Container sem limitação de CPU ou memória pode travar o host ao esgotar recursos (`fork bomb`, memory leak, etc).
* **Consequência**: Queda do sistema host.

**✅ Uso seguro:**
```bash
# Definir limites de recursos
docker run -d \
  --memory="512m" \
  --memory-swap="512m" \
  --cpus="0.5" \
  --pids-limit=100 \
  nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Sem limites de recursos (padrão)
docker run -d nginx
```

**🛡️ Como se proteger:**
```bash
# 1. SEMPRE defina limites de recursos
# 2. Monitore uso de recursos
docker stats --no-stream

# 3. Configure alertas para uso excessivo
# 4. Use --restart=on-failure com limite
docker run -d --restart=on-failure:3 nginx

# 5. Audite containers sem limites
docker ps -q | xargs docker inspect | jq -r '.[] | select(.HostConfig.Memory == 0) | .Name'
```

---

#### 🔸 `Seccomp` (Syscall Filtering)

* **Ataque**: *Uso de syscalls perigosas*.
* **Exemplo**: Se `seccomp` estiver desabilitado, pode-se usar syscalls como `ptrace`, `mount`, ou `clone` para realizar escapes ou introspecção no sistema.
* **Consequência**: Escalada de privilégios, vazamento de memória ou acesso ao host.

**✅ Uso seguro:**
```bash
# Perfil padrão (ativado por padrão)
docker run -d nginx

# Perfil customizado mais restritivo
docker run -d --security-opt seccomp=./perfil-restritivo.json nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Desabilitar seccomp completamente
docker run -d --security-opt seccomp=unconfined nginx
```

**🛡️ Como se proteger:**
```bash
# 1. NUNCA desabilite seccomp (--security-opt seccomp=unconfined)
# 2. Use perfis restritivos para aplicações específicas
# 3. Teste perfis em desenvolvimento antes de produção

# Verificar se seccomp está ativo
docker run --rm alpine grep Seccomp /proc/1/status
```

---

#### 🔸 `Capabilities` (Privilégios reduzidos)

* **Ataque**: *Uso de capabilities perigosas como `CAP_SYS_ADMIN`*.
* **Exemplo**: Um processo com `CAP_SYS_ADMIN` pode montar sistemas de arquivos, modificar a rede, e até carregar módulos do kernel.
* **Consequência**: Praticamente root do host — "a capability root".

**✅ Uso seguro:**
```bash
# Remover todas capabilities e adicionar apenas necessárias
docker run -d \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Adicionar capabilities perigosas
docker run -d --cap-add=SYS_ADMIN nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Sempre use --cap-drop=ALL como base
# 2. Adicione apenas capabilities essenciais
# 3. Evite CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_RAWIO

# Capabilities perigosas a evitar:
# - CAP_SYS_ADMIN: "a nova root"
# - CAP_SYS_MODULE: carregar módulos kernel
# - CAP_SYS_PTRACE: debug de processos
# - CAP_DAC_OVERRIDE: ignorar permissões de arquivo

# Auditar containers com capabilities perigosas
docker ps -q | xargs docker inspect | jq -r '.[] | select(.HostConfig.CapAdd[]? | contains("SYS_ADMIN")) | .Name'
```

---

#### 🔸 `AppArmor / SELinux` (LSM – Security Modules)

* **Ataque**: *Executar ações não permitidas quando políticas estão ausentes ou mal configuradas*.
* **Exemplo**: Sem AppArmor, um processo pode acessar arquivos sensíveis mesmo com permissões de sistema de arquivos fracas.
* **Consequência**: Acesso a dados restritos, comandos não auditados ou escape.
 
**✅ Uso seguro:**
```bash
# AppArmor (Ubuntu/Debian) - perfil padrão
docker run -d --security-opt apparmor=docker-default nginx

# Perfil customizado para aplicação específica
docker run -d --security-opt apparmor=perfil-custom-app nginx
```

**⛔️ Uso inseguro (evitar):**
```bash
# Desabilitar AppArmor
docker run -d --security-opt apparmor=unconfined nginx
```

**🛡️ Como se proteger:**
```bash
# 1. Mantenha LSM ativo no host
# Ubuntu: sudo aa-status
# RHEL: sudo getenforce

# 2. Use perfis específicos por aplicação
# 3. Monitore violações de política
sudo journalctl -u apparmor -f

# 4. Teste perfis em modo complain antes de enforce
sudo aa-complain /etc/apparmor.d/docker-default

# Verificar status do AppArmor em containers
docker ps -q | xargs docker inspect | jq -r '.[] | {name: .Name, apparmor: .AppArmorProfile}'
```

---

### 🧪 Exemplos reais para estudar

* **CVE-2019-5736**: Falha no `runc` que permitia *escape completo* de containers.
* **Mount Volume /docker.sock**: Quando o container tem acesso ao `docker.sock`, pode controlar todo o host Docker.
* **Default root user**: Muitas imagens Docker rodam como `root` por padrão — grande vetor de risco.

### 🔐 **Checklist de Segurança Docker**

```bash
# Script de auditoria básica
#!/bin/bash
echo "=== Docker Security Audit ==="

echo -e "\n[!] Containers rodando como root:"
docker ps -q | xargs docker inspect | jq -r '.[] | select(.Config.User == "" or .Config.User == "root") | .Name'

echo -e "\n[!] Containers com capabilities perigosas:"
docker ps -q | xargs docker inspect | jq -r '.[] | select(.HostConfig.CapAdd[]? | contains("SYS_ADMIN")) | .Name'

echo -e "\n[!] Containers sem limites de memória:"
docker ps -q | xargs docker inspect | jq -r '.[] | select(.HostConfig.Memory == 0) | .Name'

echo -e "\n[!] Containers com volumes sensíveis:"
docker ps -q | xargs docker inspect | jq -r '.[] | select(.Mounts[]?.Source == "/" or .Mounts[]?.Source == "/var/run/docker.sock") | .Name'

echo -e "\n[!] Containers com rede host:"
docker ps --format "table {{.Names}}\t{{.HostConfig.NetworkMode}}" | grep host
```

---

