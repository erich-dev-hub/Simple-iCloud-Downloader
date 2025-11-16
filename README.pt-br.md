# Simple iCloud Downloader (SiD)

[🇺🇸 Read in English](README.md)

![GitHub release (mais recente por data)](https://img.shields.io/github/v/release/erich-dev-hub/Simple-iCloud-Downloader?include_prereleases)

Uma ferramenta baseada em Python para baixar, organizar e sincronizar fotos e vídeos do iCloud para o seu armazenamento local. Ela organiza automaticamente os arquivos por `Ano/Mês` e mantém um cache local para evitar duplicatas, garantindo velocidade e integridade dos dados.

> **⚠️ AVISO LEGAL E ISENÇÃO DE RESPONSABILIDADE**
>
> **Este projeto é um utilitário pessoal criado apenas para fins educacionais.**
>
> * Não é afiliado, suportado ou aprovado pela Apple Inc.
> * O uso deste script é de responsabilidade exclusiva do usuário.
> * O autor não armazena, não coleta e não tem acesso a credenciais, fotos, vídeos ou qualquer dado do usuário.
> * Este software é fornecido "COMO ESTÁ" (AS IS), sem garantias de qualquer tipo, conforme descrito na licença MIT.
> * **Use por sua conta e risco.**

---

## 🚀 Funcionalidades

* **Sincronização Inteligente:** Baixa apenas arquivos novos (Sincronização Incremental).
* **Backup de Mão Única (Apenas Leitura):** Esta ferramenta é um *downloader*, não um espelho (two-way sync). Ela apenas lê do iCloud. O script **nunca** irá deletar, modificar ou enviar arquivos, seja no seu drive local ou na sua conta iCloud. Arquivos deletados do iCloud serão apenas ignorados em scans futuros, mas *permanecerão* no seu backup local.
* **Organização:** Organiza automaticamente os arquivos em pastas: `Pasta_Download/AAAA/AAAA_MM/`.
* **Cache Local:** Usa um índice JSON para rastrear arquivos baixados, garantindo velocidade e evitando duplicatas.
* **Salvamento em Lote (Batch Saving):** Otimiza a escrita em disco (I/O) salvando o índice apenas em intervalos específicos, protegendo a vida útil do SSD.
* **Resumível:** Pode ser interrompido (`CTRL + C` ou uma queda de energia) e retomado a qualquer momento sem corromper dados.
* **Filtro:** Opção para baixar apenas meses específicos.
* **Múltiplos Usuários:** Pode sincronizar múltiplas contas do iCloud em pastas separadas, definindo usuários/pastas em arquivos config.ini diferentes.
* **Privacidade:** Os cookies de sessão são isolados no diretório de download.
* **Menu Interativo:** Interface fácil de usar para tarefas comuns.

---

## 📋 Pré-requisitos

* **SO:** Windows 10/11 (Suporte principal), Linux ou macOS.
* **Python:** Versão 3.12 ou superior (Testado na 3.13.3).
* **Dependências:** `pyicloud`, `tqdm`, `requests`, `keyring`.

---

## ⚠️ Importante: Pré-requisitos da Conta iCloud

Para esta ferramenta funcionar, sua conta do iCloud **precisa** estar configurada com as seguintes opções. O script acessa os dados via API web oficial (simulando um navegador no iCloud.com), e estas configurações são obrigatórias.

### 1. Ativar "Acessar dados do iCloud na Web"
* **O que faz:** Esta configuração permite que sua conta seja acessada pelo site iCloud.com.
* **Onde:** No seu iPhone/iPad: `Ajustes > [Seu Nome] > iCloud > Acessar dados do iCloud na Web`
* **Estado Necessário:** **ATIVADO**
* **Erro (se errado):** Se estiver desativado, o script falhará imediatamente no login com um erro de **`ACCESS_DENIED (Falha no Login)`**.

### 2. Desativar "Proteção Avançada de Dados"
* **O que faz:** Esta é uma camada de segurança extra e opcional da Apple que fornece criptografia de ponta a ponta para fotos, backups e mais.
* **Por que é um problema:** Quando ativada, os *servidores* da Apple não possuem as chaves para descriptografar suas fotos. Como este script se conecta aos servidores (e não ao seu celular), o servidor não pode acessar os dados para enviá-los.
* **Onde:** No seu iPhone/iPad: `Ajustes > [Seu Nome] > iCloud > Proteção Avançada de Dados`
* **Estado Necessário:** **DESATIVADO**
* **Erro (se errado):** Se estiver ativado, o login e o scan funcionarão, mas todos os downloads falharão com um erro **`403 Forbidden`** (Proibido).

---

## 🐍 1. Instalação do Python

Se você não tem o Python instalado:

1. Baixe a versão mais recente compatível com Windows (3.12+):
   https://www.python.org/downloads/windows/

2. **Passo Crucial durante a instalação:**
   * ✅ Marque **"Add Python to PATH"** na parte inferior do instalador.
   * ✅ Selecione **"Customize installation"** → Marque **"Install for all users"**.

3. Após instalar, confirme a versão no Prompt de Comando:
   ```bash
   python --version
   ```

---

## 📦 2. Configurando o Ambiente Virtual (venv)

É altamente recomendado usar um ambiente virtual para manter as dependências isoladas.

1. Abra o **Prompt de Comando** ou PowerShell.
2. Navegue até a pasta onde você colocou o script:
   ```bash
   cd C:\Simple_iCloud_Downloader\
   ```
3. Crie o ambiente virtual:
   ```bash
   python -m venv venv
   ```
4. **Ative** o ambiente:
   * **Windows:**
     ```bash
     venv\Scripts\activate
     ```
   * **Linux/macOS:**
     ```bash
     source venv/bin/activate
     ```
   
   *Você verá `(venv)` aparecer no início do seu prompt.*

---

## 📥 3. Instalando Dependências

Com o ambiente virtual **ativado** (procure pelo prefixo `(venv)`), execute:

```bash
pip install pyicloud tqdm requests future keyring
```
*(Ou use `pip install -r requirements.txt` se você tiver o arquivo)*

Se o pip pedir atualização, execute:
```bash
python -m pip install --upgrade pip
```

---

## ⚙️ Configuração

Crie um arquivo chamado `config.ini` na mesma pasta do script:

```ini
[icloud]
user = seu_id_apple@email.com
download_base = C:\Backup_iCloud\Meu_Nome\Fotos
```

* **config.sample.ini**: Você pode usar o `config.sample.ini` fornecido, alterar seu conteúdo e salvar como `config.ini` para facilitar.
* **user**: Seu email do ID Apple.
* **download_base**: O caminho absoluto onde as fotos/vídeos serão salvos. Uma pasta `_cache` será criada automaticamente dentro deste diretório para armazenar o índice e os cookies de sessão.
* **Meu_Nome**: Note a pasta `Meu_Nome` no caminho de exemplo. Não é essencial e poderia ser apenas `C:\Backup_iCloud_Fotos`, mas facilita a identificação de qual usuário pertence, especialmente se você for usar este script para sincronizar mais de uma conta Apple/iCloud.
* **Múltiplos Usuários**: A conta padrão a ser sincronizada sempre busca as configurações do `config.ini`. Se você deseja sincronizar fotos e pastas de múltiplos usuários, crie arquivos de configuração separados (`config_UserA.ini`, `config_John.ini`, `config_Anna.ini`). Então, para instruir o script a usar as configurações desses outros arquivos, adicione o parâmetro `--config "config_John.ini"`.

---

## 💻 Como Usar

Certifique-se de que seu ambiente virtual está ativo (`venv\Scripts\activate`).

### Menu Interativo (Recomendado)
Simplesmente execute o script sem argumentos:

```bash
python sid.py
```

Você verá um menu como este:
```text
=== Simple iCloud Downloader - Quick Menu ===
1. Scan Files ( --scan )
2. Download Everything ( --download )
3. Download Only Specified Months ( --download --filter ... )
4. View Download Stats ( --view )
5. Terminate iCloud Session ( --logout )
q. Quit
```

### Comandos CLI (Avançado)

| Comando | Descrição |
| :--- | :--- |
| `python sid.py --scan` | Varre a biblioteca do iCloud e atualiza o índice local sem baixar conteúdo. |
| `python sid.py --download` | Baixa todos os arquivos que faltam conforme o índice. |
| `python sid.py --view` | Exibe um painel visual do progresso de download por mês (usa o índice em cache). |
| `python sid.py --logout` | Apaga os arquivos de sessão/cookies locais da pasta de cache. |

#### Avançado: Múltiplos Usuários
Para instruir o script a usar um arquivo de configuração diferente do `config.ini` padrão, permitindo assim sincronizar dados de múltiplos usuários do iCloud e em pastas diferentes:
```bash
python sid.py --download --config "outro_config.ini"
```

#### Avançado: Filtro
Para baixar apenas meses específicos (ex: Janeiro e Maio de 2023):
```bash
python sid.py --download --filter "2023-01;2023-05"
```
*Nota: A varredura (scan) é sempre realizada na biblioteca completa para manter a integridade do índice; o filtro se aplica apenas à fase de download.*

### Cenários de Uso Típicos

#### Cenário 1: O Backup Completo (Anna)
Anna quer baixar todas as suas fotos e vídeos para seu HD externo de backup.

1.  Anna conecta seu HD externo (ex: `D:\`) e seu `config.ini` aponta para `D:\iCloud_Backup\Anna`.
2.  Ela executa `python sid.py`, que abre o **Menu Rápido**. Ela seleciona a **Opção 2 (Download Everything)**.
3.  O script varre toda a biblioteca e começa a baixar todos os arquivos pendentes. Esta primeira execução pode levar muito tempo.
4.  Quando termina, ela executa `python sid.py` novamente e seleciona a **Opção 4 (View Download Stats)**. O relatório mostra 100% para todos os meses. Ela agora pode desconectar seu HD com segurança.
5.  Um mês depois, ela conecta o HD, executa `python sid.py` e seleciona a **Opção 2** novamente. O script varre rapidamente, encontra apenas as 50 novas fotos, baixa-as e termina em minutos. Seu backup está atualizado.

#### Cenário 2: O Arquivo Seletivo (John)
John quer verificar como suas fotos estão distribuídas para ver se pode remover dados antigos e liberar espaço no iCloud.

1.  John quer analisar antes de baixar. Ele executa `python sid.py --scan`. O script varre seus 70.000 itens e constrói o `index.json` local, mas não baixa nenhum conteúdo.
2.  Ele executa `python sid.py --view`. Ele vê que "2016-11" está ocupando 40 GB devido a vídeos longos que ele não precisa mais na nuvem.
3.  Para fazer backup apenas daquele mês, ele executa `python sid.py --download --filter "2016-11"`.
4.  O script varre todos os itens (para integridade), mas baixa apenas os arquivos de Novembro de 2016.
5.  Ele executa `python sid.py --view` novamente para confirmar que a linha "2016-11" agora mostra 100%. Após verificar que os arquivos estão seguros em seu drive local, ele pode deletá-los com confiança do iCloud para liberar espaço.

#### Cenário 3: O Download Resiliente (Daniel)
Daniel tem muitos terabytes de dados e sabe que o primeiro download levará dias.

1.  Ele inicia o backup executando `python sid.py` e selecionando a **Opção 2 (Download Everything)**. Ele deixa o script rodando e vai dormir.
2.  Durante a noite, uma queda de energia desliga seu computador quando o processo estava apenas na metade.
3.  No dia seguinte, Daniel liga o computador. Ele simplesmente executa `python sid.py` e seleciona a **Opção 2** novamente.
4.  O script lê instantaneamente seu cache `index.json`, reconhece as dezenas de milhares de arquivos que já baixou e os ignora. Ele automaticamente retoma o download apenas dos arquivos restantes, exatamente de onde parou.

---

## 📂 Estrutura de Diretórios

Após a execução, seu `download_base` ficará assim:

```text
C:\Backup_iCloud\Meu_Nome\Fotos\
                      ├── _cache\
                      │   ├── index.json          # Banco de dados de metadados
                      │   └── ...session files... # Cookies de autenticação (isolados por config)
                      ├── 2023\
                      │   ├── 2023_01\
                      │   │   ├── IMG_001.JPG
                      │   │   └── VIDEO_002.MOV
                      │   └── 2023_02\
                      └── 2024\
                          └── ...
```

---

## ❓ Solução de Problemas

* **Falha no Login (ACCESS_DENIED):**
  Este erro significa que suas credenciais podem estar corretas, mas sua conta está bloqueada para acesso web. Vá ao seu iPhone `Ajustes > [Seu Nome] > iCloud` e garanta que **`Acessar dados do iCloud na Web`** esteja **ATIVADO**.

* **Erro 403 Forbidden (no Download):**
  O script escaneia com sucesso, mas todos os downloads falham com um erro "403 Forbidden". Isso quase sempre significa que você está com a **`Proteção Avançada de Dados`** **ATIVADA**. Você deve desativar esta opção nos seus Ajustes do iCloud para que qualquer ferramenta web possa acessar suas fotos.

* **Erro 503 (Service Unavailable):**
  Se você vir este erro (geralmente durante o login), a Apple está limitando suas requisições temporariamente.
    * *Solução:* Aguarde 30 a 60 minutos e tente novamente.

* **Erros de "Keyring":**
  Se tiver problemas com o armazenamento de senha, garanta que o Cofre de Credenciais do seu sistema operacional (Windows Credential Locker, etc.) esteja acessível.

---

## 📄 Licença

Distribuído sob a Licença MIT. Veja o arquivo `LICENSE` para mais informações.