# SecureCorp BAC Lab - Laboratório de Broken Access Control

## 🌐 Visão Geral

Este é um laboratório de testes de segurança focado em **Broken Access Control (BAC)**, desenvolvido para simular um ambiente de Bug Bounty realista. A aplicação fictícia, **SecureCorp Solutions**, é uma plataforma de gestão corporativa intencionalmente vulnerável.

O objetivo é que o testador (Bug Hunter) encontre e explore as vulnerabilidades de controle de acesso para obter as "Flags" secretas.

## 🚀 Como Usar (Instalação Local)

Este laboratório roda diretamente em **Python 3**. Não é necessário Docker.

### Pré-requisitos
*   **Python 3.x** instalado.
*   **Pip** (gerenciador de pacotes do Python).

### Passos
1.  **Clone o Repositório:**
    ```bash
    git clone https://github.com/MATREX244/BCALAB.git
    cd BCALAB
    ```
2.  **Instale as Dependências:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Execute a Aplicação:**
    ```bash
    python app.py
    ```
4.  **Acesse o Laboratório:**
    Abra seu navegador e acesse: `http://127.0.0.1:5000`

### Credenciais Padrão
| Usuário | Senha | Papel |
| :--- | :--- | :--- |
| `admin` | `admin_secure_2026` | Administrador |
| `jdoe` | `password123` | Usuário Padrão |

## 🎯 Vulnerabilidades (As Flags)

O laboratório contém 5 vulnerabilidades de Broken Access Control. Seu objetivo é encontrar as 5 Flags.

| ID | Tipo de Vulnerabilidade | Cenário | Endpoint/Local | Flag |
| :--- | :--- | :--- | :--- | :--- |
| **BAC-01** | **IDOR (Insecure Direct Object Reference)** | Um usuário padrão pode visualizar faturas de outros usuários (incluindo o admin) alterando o ID da fatura na requisição API. | `/api/v1/invoice/<id>` | `FLAG{IDOR_INVOICE_EXPOSED_8829}` |
| **BAC-02** | **Escalação de Privilégios (Mass Assignment)** | Um usuário pode se registrar como administrador ao injetar um parâmetro oculto (`role: admin`) na requisição de registro. | `/register` (POST) | `FLAG{PRIV_ESC_VIA_REGISTRATION_9912}` |
| **BAC-03** | **Bypass de Autorização (Path Traversal Simples)** | O filtro de segurança do painel administrativo é fraco e pode ser contornado usando variações de URL. | `/admin_panel` | `FLAG{ADMIN_PATH_BYPASS_7731}` |
| **BAC-04** | **Broken Access Control em API** | Um endpoint de exportação de configurações globais não verifica o papel do usuário, permitindo que qualquer usuário logado acesse chaves de API sensíveis. | `/api/v1/settings/export` | `FLAG{SENSITIVE_EXPORT_UNPROTECTED_4421}` |
| **BAC-05** | **Bypass de Lógica (Client-Side Security)** | O acesso a recursos "Premium" é decidido no frontend. Ao interceptar e modificar a resposta do servidor para `is_premium: true`, o usuário desbloqueia o recurso e a Flag. | `/dashboard` (Lógica JS) | `FLAG{CLIENT_SIDE_PREMIUM_BYPASS_1102}` |

## 💡 Dicas para o Bug Hunter

*   Use um proxy interceptador (como Burp Suite ou OWASP ZAP) para analisar todas as requisições HTTP.
*   Preste atenção aos IDs de usuário e de objetos (faturas) nas URLs e nos corpos das requisições.
*   Tente registrar uma nova conta e manipule o corpo da requisição de registro.
*   Explore todos os endpoints da API, mesmo aqueles que não estão visíveis na interface.
*   Tente acessar URLs restritas com diferentes formatos (ex: `/admin_panel/`, `/Admin_Panel`).
