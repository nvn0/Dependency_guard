
# Dependency Guard - Overview

- NUNCA deve confiar no utilizador
- deve sempre correr análise internamente


-> Feito pra ambientes linux


# Design


## 1. Criar ambiente seguro

Cria o ambiente de desenvolvimento seguro (docker bem configurado + hardening)

Exemplo de comando:
```
safe-env create my-project
```


**O que faz:**
- cria container isolado (Docker hardened)
	- Uso da imagem slim do debian (mais minima mas com boa compatibilidade)
	- Possivel versão com alpine (precisa ponderação por causa da musl)
	- Criar com rede em modo bridge ( port bindings opcionais, talvez none, só para casos especificos)
- aplica:
	- seccomp profile
	- AppArmor
	- limites de FS (~/.ssh, passwd)
	- regras de iptables
		- `iptables -I DOCKER-USER -i docker0 ! -d 172.17.0.0/16 -j DROP` -> apenas localhost -> Allow localhost only;
		- `iptables -I DOCKER-USER -i docker0 -j DROP` -> aplica a todos os containers -> Apenas para lockdown geral;

- prepara:
	- cgroup dedicado (para eBPF)
	- eBPF (controla syscalls, rede, acessos ao filesystem)
	- policy base (definir politicas num toml/yaml/json)
	- cria workspace isolado (sem acesso ao host real)


## 2. Instalar libs no ambiente criado + verificações

Comando de instalar/atualizar

Exemplo de comando:
```
safe-env install myproject npm install
```

ou:

```
safe-env add axios
```


### O que faz:

**Fase 1 - Pre-check (antes de executar)**

- verificar metadata:
	- mudança de email/assinaturas
	- versão vs Git tag (axios falhou aqui )


- diff de dependências:
	- nova dependency suspeita (ex: plain-crypto-js)


- delay:
	- pacote publicado há < X horas → bloquear


<br>

**Fase 2 - Execução controlada**

correr install dentro do container eBPF ativo:


bloquear:
- ~/.ssh
- .env
- /etc/passwd
- bloquear rede



Usar whitelist:
- IP's
- Dominios
- Instalar/atualizar libs


<br>

`tracepoint/syscalls/sys_enter_connect` → bloqueia connects não-whitelisted
`tracepoint/syscalls/sys_enter_execve` → bloqueia /bin/bash, /bin/sh
`tracepoint/syscalls/sys_enter_openat` → bloqueia acesso a ~/.ssh, /etc/passwd, .env



**Fase 3 - Runtime enforcement**

Se acontecer:
- connect() → BLOCK
- execve bash/curl → ALERT/BLOCK
- file read sensível → BLOCK


(isto matava o RAT do axios logo no início)

<br>

**Fase 4 - Pós-validação**

- Verificar:
	- diff do filesystem

- detectar:
	- binários novos
	- scripts persistentes

- verificar integridade final


Output tipo:

```
⚠ axios@1.14.1
- dependency nova: plain-crypto-js
- versão não existe no Git
- tentativa de network detectada
  
❌ bloqueado
```



## 3. Comando de analise

- Deve analisar **o que vai ser** instalado / atualizado


Exemplo:
```
safe-env analyze myproject npm install
```



Output tipo:

```
⚠ axios@1.14.1
- dependency nova: plain-crypto-js
- versão não existe no Git
- tentativa de network detectada
  
❌ bloqueado
```



analisa:
- dependências que vão ser resolvidas
- novas versões
- novas dependências transitivas


**Deve fazer:**
- checks de metadata
- diff de dependências
- verificar assinaturas / hashes
- simular install (sandbox opcional)
- detectar comportamento suspeito


### Variante - analisar o que está intalado

Exemplo:
```
safe-env analyze --installed
```

analisa:
- o que já está em node_modules
- alterações no filesystem
- integridade atual

útil para:
- auditoria
- detectar compromissos pós-install



### Variante - analisar um possivel update (já é o conceito do funcionamento normal do comando de analise, mas ya fica aí)

Exemplo:
```
safe-env analyze --update
```
- usado antes do update


analisa:
- upgrades possíveis
- riscos das novas versões




## 4. Comando de update



Exemplo:
```
safe-env update myproject
```

O que deve fazer:
- detectar updates disponíveis
- comparar lockfile vs registry


**para cada update:**

ex: axios: 1.13.0 → 1.14.1


executar:
- diff de deps
- metadata check
- delay policy
- análise comportamental (opcional sandbox)

decisão:
```
✔ safe → atualizar
⚠ suspeito → bloquear
```


# Comandos:

## Core:
```
safe-env init myproject    # cria ambiente seguro
safe-env start myproject
safe-env stop myproject
safe-env install myproject npm install    # instala (no ambiente) com enforcement
safe-env analyze myproject npm install    # análise sem executar (verificar possiveis updates)
safe-env update myproject  # atualiza dependências
safe-env <project> audit # mostra libs instaladas, versao, etc
```


## Extras:

```
safe-env net localhost
safe-env net block
safe-env policy
safe-env logs
safe-env diff
safe-env trust
```