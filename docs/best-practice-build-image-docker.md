### ✨ Objetivos e Práticas para Imagens Docker de Qualidade

---

### 🌟 Objetivos de uma Imagem Docker de Qualidade

#### 📦 1. **Ser pequena**

> **Reduz o tempo de download, consumo de banda e espaço em disco.**

* Menos pacotes = menos CVEs
* Facilita deploys rápidos e enxutos
* Melhora o cold start de containers
* Menor custo de armazenamento em nuvem
* Menor custo de transferência de dados

#### ⚡ 2. **Ser rápida para construir**

> **Acelera o ciclo de desenvolvimento e CI/CD.**

* Instruções organizadas para maximizar cache
* `.dockerignore` bem configurado
* Uso de cache com `RUN --mount=type=cache`
* Dependências instaladas no topo do Dockerfile
* Menos custo computacional e de energia

#### 🔐 3. **Ser segura**

> **Reduz a superfície de ataque e riscos em produção.**

* Imagens mínimas (Alpine, Distroless)
* Princípio do menor privilégio
* Rodar como usuário não-root
* Remover ferramentas desnecessárias (ex: `curl`, `git`, `bash`)
* Evitar credenciais embutidas
* Multi-stage build para separar build/runtime
* Uso de `--network=none` e `RUN --mount=type=secret` quando necessário

#### 🔁 4. **Ser cacheável**

> **Permite builds incrementais e reprodutíveis.**

* Instruções organizadas do menos mutável ao mais mutável
* Evitar comandos não determinísticos (`RUN date`, `apt-get update` sem install)
* Fixar versões de pacotes quando necessário
* Uso de cache de build (`RUN --mount=type=cache`) para pip, npm, composer, maven, etc.

#### 📛 5. **Ser legível e manutenível**

> **Facilita entendimento e modificações por outras pessoas (ou você no futuro).**

* Comentários explicando decisões técnicas importantes
* Uso claro de `AS` em multi-stage
* Organização lógica do Dockerfile
* Separação de responsabilidades (build, runtime, testes, etc.)

#### 🚢 6. **Ser portátil**

> **Funciona da mesma forma em diferentes ambientes (local, CI/CD, produção).**

* Evita caminhos absolutos e dependência do host
* Usa apenas o necessário dentro da imagem
* Não depende de recursos externos não controlados (ex: APIs externas, arquivos locais não copiados)

---

### 🛠️ Práticas Concretas para Atingir os Objetivos

#### 🏦 Escolha da imagem base

* Usar imagens otimizadas: `alpine`, `slim`, `distroless`
* Evitar `latest` e preferir versões fixas

#### ⚖️ Organização do Dockerfile

* Preparar dependências no topo
* Instruções do menos mutável para o mais mutável
* Usar `.dockerignore` para evitar arquivos desnecessários

#### 📁 Multi-stage builds

* Etapas separadas para build e runtime
* Reduz tamanho e elimina ferramentas de compilação

#### 🔄 Cache de build

* Usar cache tradicional com `COPY e RUN` de forma adequada, ou seja, quando for necessário fazer cache de uma camada inteira baseada em arquivos específicos.
* Usar `RUN --mount=type=cache` para diretórios como `/root/.cache`, `/var/cache/apt`, etc.
* Usar `RUN --mount=type=bind` para arquivos temporários (ex: `requirements.txt`)
* Fixar versões em `apt`, `pip`, `npm` etc.

#### 🔐 Segurança

* Rodar como usuário não-root (`USER`)
* Remover ferramentas e dependências desnecessárias após uso
* Usar apenas imagens oficiais e mantidas
* Usar `--network=none` e `--mount=type=secret` onde aplicável
* Evitar embutir arquivos sensíveis (`.env`, `.ssh`, `.aws`, etc.)

#### 💡 Reprodutibilidade

* Evitar comandos não determinísticos
* Fixar versões sempre que possível

---

> Uma imagem Docker bem projetada é mais do que funcional: é leve, segura, fácil de manter e previsível em qualquer ambiente.
