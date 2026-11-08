# Catálogo de opções

> Gerado a partir de `src/nmap/catalog.rs` (`nscope --print-catalog`). Não edite à mão.

## Técnica de scan

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| — | Técnica principal | Define COMO o nmap testa cada porta (ou se ele só descobre hosts). É a escolha mais importante do scan. |  |
| ↳ (padrão) | Automático | O nmap decide: usa SYN (-sS) se você é administrador; senão usa conexão completa (-sT). |  |
| ↳ `-sL` | Só listar alvos (-sL) | List Scan: apenas lista e resolve os alvos, sem enviar nenhum pacote a eles. Ótimo para conferir o escopo antes de escanear. |  |
| ↳ `-sn` | Só descobrir hosts (-sn) | Ping scan: descobre quais hosts estão ligados, sem escanear portas. Primeiro passo para mapear uma rede. |  |
| ↳ `-sS` | TCP SYN (-sS) | Scan "meio-aberto": envia SYN e, se vier SYN/ACK, não completa a conexão. Rápido e pouco registrado nos logs. | exige |
| ↳ `-sT` | TCP conexão completa (-sT) | Abre conexões TCP completas pelo sistema operacional. Funciona sem privilégios, mas é mais lento e deixa mais rastros. |  |
| ↳ `-sA` | TCP ACK (-sA) | Não descobre portas abertas: mapeia regras de firewall, dizendo se as portas são "filtradas" ou "não filtradas". | exige |
| ↳ `-sW` | TCP Window (-sW) | Parecido com o ACK, mas examina o tamanho da janela TCP; em alguns sistemas separa aberta de fechada. | exige |
| ↳ `-sM` | TCP Maimon (-sM) | Envia FIN/ACK. Só funciona em alguns sistemas BSD antigos; útil em cenários muito específicos. | exige |
| ↳ `-sN` | TCP Null (-sN) | Pacote TCP sem nenhuma flag. Portas fechadas respondem RST; abertas ficam em silêncio. Tenta driblar firewalls sem estado. | exige |
| ↳ `-sF` | TCP FIN (-sF) | Envia só a flag FIN. Mesma lógica do Null scan. | exige |
| ↳ `-sX` | TCP Xmas (-sX) | Liga as flags FIN, PSH e URG ("árvore de Natal"). Mesma lógica do Null scan. | exige |
| ↳ `-sY` | SCTP INIT (-sY) | O "SYN scan" do protocolo SCTP, usado em telecom. | exige |
| ↳ `-sZ` | SCTP COOKIE-ECHO (-sZ) | Variação mais furtiva do scan SCTP. | exige |
| ↳ `-sO` | Protocolos IP (-sO) | Descobre quais protocolos IP (ICMP, TCP, UDP, GRE...) o alvo aceita, em vez de portas. | exige |
| ↳ `-sI` | Idle / zumbi (-sI) | Escaneia usando um "zumbi" como intermediário; seu IP não aparece para o alvo. Avançado e raramente funciona hoje. | exige |
| ↳ `-b` | FTP bounce (-b) | Usa um servidor FTP vulnerável como intermediário. Técnica antiga: quase todos os servidores já bloqueiam. |  |
| `-sI` | Host zumbi | O host intermediário usado no idle scan. Precisa estar ocioso e ter um contador de IP ID previsível. Formato: host[:porta]. |  |
| `-b` | Servidor FTP relay | O servidor FTP usado como intermediário. Formato: usuario:senha@servidor:porta. |  |
| `-sU` | Escanear também UDP | Testa portas UDP (DNS 53, SNMP 161, DHCP, NTP...). Pode ser combinado com uma técnica TCP. Sozinho, escaneia só UDP. | exige |
| `--scanflags` | Flags TCP personalizadas | Monte seu próprio pacote TCP escolhendo as flags (URG, ACK, PSH, RST, SYN, FIN) ou um número. Substitui as flags da técnica TCP escolhida. | exige |

## Descoberta de hosts

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-Pn` | Pular a descoberta de hosts | Escaneia as portas mesmo que o host não responda ao teste "você está ligado?". Trata todos os alvos como ligados. |  |
| `-PS` | Ping TCP SYN (portas) | Envia um SYN às portas indicadas. Qualquer resposta (SYN/ACK ou RST) prova que o host está ligado. | melhor com |
| `-PA` | Ping TCP ACK (portas) | Envia um ACK; hosts ligados respondem com RST. Passa por firewalls simples que só bloqueiam conexões novas (SYN). | melhor com |
| `-PU` | Ping UDP (portas) | Envia um pacote UDP; um host ligado costuma responder "porta inacessível" (ICMP). | exige |
| `-PY` | Ping SCTP INIT (portas) | Descobre hosts que usam o protocolo SCTP (comum em telecom). | exige |
| `-PE` | Ping ICMP echo | O "ping" clássico: pergunta "você está aí?" por ICMP echo request. Já faz parte da descoberta padrão em redes locais. | melhor com |
| `-PP` | Ping ICMP timestamp | Pede a hora ao host por ICMP. Alguns firewalls bloqueiam o echo, mas deixam esta consulta passar. | melhor com |
| `-PM` | Ping ICMP máscara de rede | Pede a máscara de rede por ICMP address mask. Mais um jeito de achar hosts que ignoram o ping comum. | melhor com |
| `-PO` | Ping por protocolo IP | Envia pacotes IP com os números de protocolo indicados (1 = ICMP, 2 = IGMP, 4 = IP-in-IP). | exige |
| — | Resolução de DNS | Controla se o nmap consulta o DNS para trocar IPs por nomes (DNS reverso). |  |
| ↳ (padrão) | Padrão (só quando necessário) | O nmap resolve o nome dos hosts que estão ligados. |  |
| ↳ `-n` | Nunca (-n) | Não consulta DNS. Fica mais rápido e mais discreto; você verá só IPs. |  |
| ↳ `-R` | Sempre (-R) | Resolve o DNS reverso de todos os IPs, inclusive dos desligados. |  |
| `--dns-servers` | Servidores DNS próprios | Usa estes servidores DNS (separe por vírgula) em vez dos configurados no sistema. |  |
| `--system-dns` | Usar o DNS do sistema | Usa a resolução de nomes do sistema operacional. Mais lento, mas respeita /etc/hosts e o DNS interno da empresa. |  |
| `--traceroute` | Traçar a rota até o alvo | Mostra por quais roteadores o tráfego passa até chegar ao alvo (cada passagem é um "salto"). | exige |

## Portas

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| — | Quais portas escanear | Cada serviço de rede escuta em uma porta (web: 80/443, SSH: 22). Aqui você escolhe quantas e quais testar. |  |
| ↳ (padrão) | Padrão: 1000 mais comuns | Cobre as 1000 portas mais usadas, segundo a base do nmap. Serve para a maioria dos casos. |  |
| ↳ `-F` | Rápido: 100 mais comuns (-F) | Testa só as 100 portas mais comuns. Bem mais rápido, mas pode perder serviços incomuns. |  |
| ↳ `-p-` | Todas as 65535 (-p-) | Testa todas as portas. Acha serviços escondidos em portas altas, mas demora bem mais. |  |
| ↳ `-p` | Lista ou faixa (-p) | Você escolhe: 22,80,443 ou 1-1024 ou T:80,U:53 (T = TCP, U = UDP). |  |
| ↳ `--top-ports` | N mais comuns (--top-ports) | As N portas mais frequentes segundo a base de dados do nmap. |  |
| ↳ `--port-ratio` | Por frequência (--port-ratio) | Testa portas cuja frequência de uso é maior que a razão informada (0.0 a 1.0). |  |
| `-p` | Lista de portas | Portas exatas a testar. Aceita números, faixas e prefixos de protocolo. |  |
| `--top-ports` | Quantidade de portas | Quantas das portas mais comuns testar. |  |
| `--port-ratio` | Razão de frequência | Número entre 0.0 e 1.0. Quanto maior, menos portas (só as mais comuns). |  |
| `--exclude-ports` | Excluir portas | Pula estas portas mesmo que estejam dentro da faixa escolhida. Útil para evitar portas que travam equipamentos frágeis. |  |
| `-r` | Portas em ordem sequencial | Não embaralha a ordem das portas. Por padrão o nmap as embaralha para distribuir a carga e dificultar a detecção. |  |

## Serviços e SO

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-sV` | Detectar serviço e versão | Além de saber que a porta está aberta, pergunta ao serviço quem ele é: "nginx 1.18" em vez de só "http". Essencial para achar software desatualizado. |  |
| `--version-intensity` | Intensidade da detecção (0 a 9) | Quão fundo o nmap tenta identificar o serviço. 0 usa só as sondas mais prováveis; 9 tenta todas. O padrão é 7. |  |
| `--version-light` | Detecção leve (intensidade 2) | Atalho para --version-intensity 2: rápido, identifica os serviços mais óbvios. |  |
| `--version-all` | Detecção exaustiva (intensidade 9) | Atalho para --version-intensity 9: tenta todas as sondas em cada porta aberta. Lento, porém o mais completo. |  |
| `--version-trace` | Mostrar detalhes da detecção | Imprime o que o nmap enviou e recebeu durante a detecção de versão. Para depurar resultados estranhos. |  |
| `-O` | Detectar sistema operacional | Analisa detalhes do tráfego TCP/IP (a "impressão digital") para adivinhar se o alvo é Linux, Windows, roteador etc. | exige |
| `--osscan-limit` | Limitar a detecção de SO | Só tenta detectar o SO em hosts promissores (com ao menos uma porta aberta e uma fechada). Economiza tempo em redes grandes. Exige -O. |  |
| `--osscan-guess` | Palpites de SO mais agressivos | Mostra palpites mesmo quando a confiança é baixa. Exige -O. |  |
| `-A` | Modo agressivo (tudo junto) | Atalho que liga detecção de SO (-O), de versão (-sV), scripts padrão (-sC) e traceroute (--traceroute). | exige |

## Scripts (NSE)

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-sC` | Scripts padrão (categoria default) | Roda os scripts NSE da categoria "default": leem banners, certificados TLS, títulos de sites, métodos HTTP e outras informações úteis, sem tentar invadir nada. |  |
| `--script` | Scripts específicos | Roda scripts NSE por nome, categoria (default, safe, vuln...), padrão com * ou caminho. Combine com vírgula; use and, or e not para expressões. Use o navegador de scripts abaixo (Enter/Espaço) para montar a lista. |  |
| `--script-args` | Argumentos dos scripts | Passa parâmetros aos scripts no formato chave=valor, separados por vírgula. |  |
| `--script-args-file` | Argumentos dos scripts (arquivo) | Lê os argumentos dos scripts de um arquivo. |  |
| `--script-trace` | Rastrear a comunicação dos scripts | Mostra todos os dados enviados e recebidos pelos scripts. Para depurar. |  |
| `--script-updatedb` | Atualizar a base de scripts | Reconstrói o índice de scripts (script.db). Rode depois de instalar scripts novos. Não faz scan. |  |
| `--script-help` | Ajuda de um script | Mostra a descrição de um script (ou de uma categoria) e sai, sem escanear nada. |  |

## Tempo e desempenho

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| — | Modelo de velocidade (-T) | Um atalho que ajusta vários tempos e limites de uma vez. Quanto maior o número, mais rápido e mais barulhento. |  |
| ↳ (padrão) | Normal (T3, padrão) | Equilíbrio entre velocidade e segurança. É o padrão do nmap. |  |
| ↳ `-T0` | Paranoico (-T0) | Espera cerca de 5 minutos entre sondas. Serve para driblar sistemas de detecção, mas um scan pode levar dias. |  |
| ↳ `-T1` | Furtivo (-T1) | Espera cerca de 15 segundos entre sondas. Muito lento. |  |
| ↳ `-T2` | Educado (-T2) | Reduz a velocidade para usar menos banda e menos recursos do alvo (espera cerca de 0,4 s). |  |
| ↳ `-T4` | Agressivo (-T4) | Assume uma rede rápida e confiável. Bom para redes locais e laboratórios. |  |
| ↳ `-T5` | Insano (-T5) | Velocidade máxima sacrificando precisão. Pode perder portas e derrubar equipamentos frágeis. |  |
| `--min-hostgroup` | Mín. de hosts por grupo | O nmap escaneia hosts em grupos. Define o tamanho mínimo do grupo (mais hosts em paralelo). |  |
| `--max-hostgroup` | Máx. de hosts por grupo | Limita o tamanho do grupo de hosts escaneados ao mesmo tempo. Útil para ver resultados mais cedo. |  |
| `--min-parallelism` | Mín. de sondas em paralelo | Força um mínimo de sondas simultâneas por grupo. Acelera, com risco de perder precisão. |  |
| `--max-parallelism` | Máx. de sondas em paralelo | Limita sondas simultâneas. Use 1 para enviar uma sonda por vez (lento e discreto). |  |
| `--min-rtt-timeout` | Tempo mínimo de espera por resposta | Menor tempo que o nmap espera por uma resposta antes de reenviar a sonda. |  |
| `--max-rtt-timeout` | Tempo máximo de espera por resposta | Maior tempo que o nmap espera por uma resposta. Reduza em redes locais rápidas. |  |
| `--initial-rtt-timeout` | Tempo inicial de espera | Tempo de espera inicial por resposta, antes de o nmap aprender o tempo real da rede. |  |
| `--max-retries` | Máx. de retransmissões | Quantas vezes reenviar uma sonda sem resposta. Menos tentativas = mais rápido, porém pode perder portas. |  |
| `--host-timeout` | Tempo limite por host | Desiste de um host que demorar mais que isso. Evita que um alvo lento trave o scan inteiro. |  |
| `--scan-delay` | Pausa entre sondas | Espera este tempo entre cada sonda enviada a um host. Contorna limites de taxa e reduz ruído. |  |
| `--max-scan-delay` | Pausa máxima entre sondas | Limite superior para a pausa que o nmap aumenta sozinho quando percebe perda de pacotes. |  |
| `--min-rate` | Taxa mínima (pacotes/s) | Garante que o nmap envie pelo menos esta quantidade de pacotes por segundo. |  |
| `--max-rate` | Taxa máxima (pacotes/s) | Nunca envia mais que isso por segundo. Ótimo para não saturar links lentos. |  |
| `--defeat-rst-ratelimit` | Ignorar limite de RST | Alguns alvos limitam quantos pacotes RST enviam, o que atrasa o scan. Esta opção acelera, ao custo de marcar mais portas como "filtradas". |  |
| `--defeat-icmp-ratelimit` | Ignorar limite de ICMP | Equivalente para scans UDP: alvos que limitam respostas ICMP "porta inacessível". Mais rápido, menos preciso. |  |

## Evasão e firewall

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-f` | Fragmentar pacotes | Divide os pacotes IP em fragmentos pequenos (8 bytes) para dificultar a análise por firewalls e IDS simples. | exige |
| `--mtu` | Tamanho do fragmento (MTU) | Define o tamanho dos fragmentos (precisa ser múltiplo de 8). Substitui -f. | exige |
| `-D` | Iscas (decoys) | Mistura seu IP real com IPs falsos ("iscas") para o alvo não saber qual é o verdadeiro. ME marca a posição do seu IP; RND:n gera n iscas aleatórias. | exige |
| `-S` | Falsificar o IP de origem | Envia os pacotes como se viessem de outro IP. As respostas voltam para esse IP, não para você. | exige |
| `-e` | Interface de rede | Força o uso de uma interface específica (eth0, wlan0...). Útil com mais de uma placa de rede ou com -S. |  |
| `-g` | Porta de origem fixa | Usa esta porta como origem dos pacotes (--source-port). Alguns firewalls mal configurados aceitam tráfego vindo da porta 53 (DNS) ou 20 (FTP-data). |  |
| `--proxies` | Passar por proxies | Encaminha as conexões TCP por proxies HTTP ou SOCKS4 (URLs separadas por vírgula). |  |
| `--data` | Payload em hexadecimal | Anexa estes bytes (em hexadecimal) aos pacotes enviados. |  |
| `--data-string` | Payload em texto | Anexa este texto aos pacotes enviados. |  |
| `--data-length` | Dados aleatórios extras | Anexa N bytes aleatórios aos pacotes, para que não tenham o tamanho típico de um scan do nmap. |  |
| `--ip-options` | Opções do cabeçalho IP | Envia pacotes com opções IP: R (registrar rota), T (carimbo de tempo), L/S (roteamento de origem) etc. | exige |
| `--ttl` | TTL dos pacotes | Define o tempo de vida (TTL) dos pacotes IP. Afeta até quantos roteadores eles chegam. |  |
| `--spoof-mac` | Falsificar o MAC | Usa outro endereço MAC. Valores: 0 (aleatório), um MAC completo, um prefixo ou o nome de um fabricante (Apple, Cisco...). | exige |
| `--badsum` | Checksum inválido | Envia pacotes com checksum errado. Um host de verdade descarta; firewalls e IDS mal feitos podem responder, revelando que existem. | exige |

## Saída e relatórios

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-oN` | Salvar em texto normal | Mesmo formato que você vê na tela. Informe um nome de arquivo. |  |
| `-oX` | Salvar em XML | Formato para programas lerem (e o que o nscope usa para montar os Resultados). Informe um nome de arquivo. |  |
| `-oG` | Salvar em formato grepável | Uma linha por host, fácil de filtrar com grep. Formato legado: prefira XML. |  |
| `-oS` | Salvar em "script kiddie" | Texto em leetspeak (m4s n1ng43m 1550). Só por diversão. |  |
| `-oA` | Salvar nos 3 formatos | Salva em texto, XML e grepável de uma vez, usando o nome-base informado (cria .nmap, .xml e .gnmap). |  |
| — | Nível de detalhes (-v) | Mostra mais informações durante o scan (portas abertas assim que são achadas, estimativas de tempo...). |  |
| ↳ (padrão) | Normal | Saída padrão. |  |
| ↳ `-v` | Detalhado (-v) | Mostra portas abertas assim que são descobertas e progresso. |  |
| ↳ `-vv` | Mais detalhado (-vv) | Ainda mais informação sobre o que o nmap está fazendo. |  |
| ↳ `-vvv` | Máximo (-vvv) | O nível mais verboso. |  |
| — | Nível de depuração (-d) | Mostra informação interna do nmap para investigar problemas. |  |
| ↳ (padrão) | Desligado | Sem depuração. |  |
| ↳ `-d` | Básico (-d) | Depuração básica. |  |
| ↳ `-dd` | Intermediário (-dd) | Depuração intermediária. |  |
| ↳ `-ddd` | Intenso (-ddd) | Depuração intensa. |  |
| `--reason` | Mostrar o motivo de cada estado | Explica por que cada porta está aberta, fechada ou filtrada (ex.: "syn-ack", "reset", "no-response"). |  |
| `--open` | Mostrar só portas abertas | Esconde portas fechadas e filtradas da saída. Deixa o relatório bem mais limpo. |  |
| `--packet-trace` | Mostrar todos os pacotes | Imprime cada pacote enviado e recebido. Muito longo; use em poucas portas para entender o que acontece na rede. |  |
| `--iflist` | Listar interfaces e rotas | Mostra as interfaces de rede e rotas que o nmap enxerga e sai. Para depurar problemas de rede. |  |
| `--append-output` | Acrescentar ao arquivo | Adiciona o resultado ao final dos arquivos de saída em vez de sobrescrevê-los. |  |
| `--resume` | Retomar scan interrompido | Continua um scan interrompido a partir do arquivo de saída normal (-oN) ou grepável (-oG). As demais opções vêm do arquivo. |  |
| `--noninteractive` | Desligar teclas durante o scan | Por padrão, teclas como v, d e p alteram o nível de detalhe durante o scan. Esta opção desliga isso (útil em scripts e agendamentos). |  |
| `--stylesheet` | Folha de estilo (XSL) | Define o XSL usado para transformar o XML em HTML ao abrir no navegador. |  |
| `--webxml` | Usar estilo do nmap.org | Referencia a folha de estilo do site do nmap, para o XML abrir bonito em qualquer computador. |  |
| `--no-stylesheet` | Sem folha de estilo | Não associa nenhuma folha de estilo ao XML. |  |
| `--stats-every` | Relatório de progresso periódico | Imprime o andamento do scan neste intervalo. O nscope já usa 1s por conta própria quando você não define. |  |
| `--log-errors` | Registrar erros no arquivo | Grava erros e avisos também nos arquivos de saída normal. |  |

## Avançado

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| `-6` | Escanear IPv6 | Ativa o suporte a IPv6. Os alvos devem ser endereços IPv6 ou nomes com registro AAAA. |  |
| `--datadir` | Pasta de dados do nmap | Usa uma pasta personalizada para os arquivos de dados (bases de serviços, de SO e scripts). |  |
| — | Camada de envio | Força como o nmap envia os pacotes. |  |
| ↳ (padrão) | Automático | O nmap escolhe a melhor opção. |  |
| ↳ `--send-eth` | Quadros Ethernet (--send-eth) | Envia na camada 2 (Ethernet), em vez de pela camada IP. | exige |
| ↳ `--send-ip` | Pacotes IP (--send-ip) | Envia na camada 3 (IP), em vez de quadros Ethernet. | exige |
| — | Modo de privilégios | Diz ao nmap (e ao nscope) como tratar os privilégios, ignorando a detecção automática. Útil quando o nmap tem capabilities no Linux. |  |
| ↳ (padrão) | Detectar sozinho | O nmap verifica se você pode usar sockets brutos. |  |
| ↳ `--privileged` | Assumir administrador (--privileged) | Assume que você tem todos os privilégios (útil em sistemas com capabilities). |  |
| ↳ `--unprivileged` | Assumir usuário comum (--unprivileged) | Assume que você não tem privilégios de sockets brutos. |  |
| `-V` | Mostrar a versão do nmap | Imprime a versão e sai. |  |
| `-h` | Mostrar a ajuda do nmap | Imprime o resumo de opções e sai. |  |
| — | Flags extras (campo livre) | Qualquer opção que não aparece nas listas, escrita como no terminal. É a válvula de escape para cobrir 100% do nmap. Nunca passa por shell. |  |

## Alvo

| Flag | Opção | O que faz | Admin |
|---|---|---|---|
| — | Alvos | Quem será escaneado: um IP, um nome de máquina, uma rede inteira (CIDR) ou uma faixa. Separe vários alvos com espaço ou vírgula. |  |
| `-iL` | Lista de alvos em arquivo | Lê os alvos de um arquivo de texto (um por linha ou separados por espaço). Use "-" para ler da entrada padrão. |  |
| `-iR` | Alvos aleatórios | Escolhe N endereços IP aleatórios da internet para escanear. |  |
| `--exclude` | Excluir alvos | Retira hosts ou redes do scan (separe por vírgula). Ideal para proteger o seu próprio IP ou servidores críticos que não podem ser incomodados. |  |
| `--excludefile` | Excluir alvos (arquivo) | Igual a --exclude, mas lê a lista de um arquivo. |  |
