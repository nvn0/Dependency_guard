# AppArmor Custom Profiles

## nodejs-restricted

Um perfil AppArmor mais restrito especificamente para ambientes Node.js em containers Docker.

### Características de Segurança:

**Capabilities Bloqueadas:**
- `sys_admin` - Não permitir operações administrativas do sistema
- `sys_module` - Não permitir carregamento de módulos do kernel
- `sys_ptrace` - Não permitir rastreamento de processos
- `sys_rawio` - Não permitir acesso direto ao hardware

**Acesso de Ficheiros:**
- Root filesystem em read-only (excepto paths necessários)
- `/app/`, `/home/`, `/opt/` para aplicação Node.js
- `/tmp/` e `/var/tmp/` restritos apenas aos diretórios da aplicação
- Acesso negado a `/root/`, `.ssh/`, `/etc/shadow`

**Rede:**
- IPv4 e IPv6 permitidos (para conectividade da aplicação)
- Sockets UNIX permitidos
- Raw sockets bloqueados

**Processos:**
- Signals apenas entre processos próprios
- ptrace bloqueado
- Mount/umount bloqueado

### Como usar:

1. **Usar o script de instalação automática** (recomendado):
```bash
sudo ./setup_apparmor.sh
```
Este script irá:
- Copiar os perfis para `/etc/apparmor.d/`
- Carregar os perfis no AppArmor
- Recarregar o serviço AppArmor
- Os perfis ficam persistentes no boot

2. **Instalação manual**:
```bash
# Copiar o perfil
sudo cp apparmor_custom_profiles/nodejs-restricted /etc/apparmor.d/

# Definir permissões
sudo chmod 644 /etc/apparmor.d/nodejs-restricted

# Carregar o perfil
sudo apparmor_parser -r /etc/apparmor.d/nodejs-restricted

# Recarregar o serviço
sudo systemctl reload apparmor
```

3. **Usar no create.go**:
```go
SecurityOpt: []string{
    "apparmor=nodejs-restricted",
    "no-new-privileges",
    "seccomp=default.json",
}
```
