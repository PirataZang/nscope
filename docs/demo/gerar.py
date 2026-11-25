#!/usr/bin/env python3
"""Gera os vídeos (MP4 30 fps) e GIFs do README gravando o nscope de verdade.

Uso (na raiz do repositório, com `nscope` e `nmap` no PATH):
    python3 -m venv .venv && .venv/bin/pip install pyte pillow
    .venv/bin/python docs/demo/gerar.py fluxo configurar seguranca capturas
    .venv/bin/python docs/demo/gerar.py fluxo --texto      # só mostra as telas, não gera vídeo
    .venv/bin/python docs/demo/gerar.py fluxo --reusar     # re-renderiza a última gravação (sem rodar o nmap de novo)

O único alvo escaneado é scanme.nmap.org (o projeto Nmap permite, com moderação).
O alvo 8.8.8.8 do vídeo de segurança só é digitado: a confirmação é cancelada e nada é executado.
Requer: python3, pyte, pillow, ffmpeg.
"""

import os
import pickle
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MEDIA = os.path.join(ROOT, "docs", "media")
LOG = []  # telas capturadas em pontos de controle (para conferir o roteiro)


def novo():
    os.environ["PATH"] = os.path.expanduser("~/.cargo/bin") + os.pathsep + os.environ["PATH"]
    return engine.Demo(cwd=tempfile.mkdtemp(prefix="nscope-demo-"))


def ponto(d, nome):
    LOG.append(f"----- {nome} (t={d.now:.1f}s)\n" + "\n".join(l.rstrip() for l in d.screen.display))


def apagar(d, n):
    for _ in range(n):
        d.key("backspace", hold=0.035, show=False)


# --------------------------------------------------------------------------- roteiros

def fluxo(d):
    """Alvo → perfil → comando explicado → execução real → resultados."""
    d.wait(1.2)
    d.caption("nscope · o nmap sem decorar flags")
    d.wait(2.4)
    d.caption("1 · Escolha o alvo (scanme.nmap.org é liberado pelo projeto Nmap)")
    d.focus(23, 6, 46)
    d.click_text("Alvos", dur=1.0)  # clicar na linha abre a edição
    ponto(d, "edicao do alvo")
    d.wait(0.6)
    d.key("enter")
    d.focus(30, 25, 60, dur=1.2)
    d.caption("O comando aparece sempre aqui, colorido, pronto para copiar")
    d.wait(2.6)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("2 · Escolha um perfil pronto")
    d.click_text("Perfis", dur=0.9)
    d.wait(0.5)
    d.click_text("Scan rápido", dur=0.8)
    d.focus(71, 9, 58, dur=1.2)
    d.wait(1.0)
    d.caption("Cada perfil diz quando usar e o quão barulhento ele é")
    d.wait(2.4)
    d.key("enter")
    d.focus(30, 25, 60, dur=1.0)
    d.wait(1.4)
    d.focus(50, 14, 104, dur=1.0)
    d.caption("Ajuste fino: ligue a detecção de versão dos serviços")
    d.click_text("Configurar", dur=0.9)
    d.click_text("Serviços e SO", dur=0.8)
    d.focus(35, 8, 70, dur=1.1)
    d.wait(0.6)
    d.key("enter")
    d.focus(30, 25, 60, dur=1.0)
    d.wait(1.8)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("3 · Revise: cada pedaço do comando é explicado")
    d.click_text("Comando", dur=0.9)
    d.wait(0.6)
    d.focus(34, 9, 70, dur=1.3)
    ponto(d, "comando explicado")
    d.wait(3.2)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("4 · Execute e acompanhe o progresso (a espera foi acelerada 3×)")
    d.click_text("Executar (r)", dur=1.2, pause=0.6)
    d.focus(46, 9, 92, dur=1.1)
    d.wait_for("Concluído", timeout=180, speed=3)
    ponto(d, "execucao concluida")
    d.wait(1.8)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("5 · Resultados navegáveis: hosts, portas e o que cada uma significa")
    d.click_text("Resultados", dur=1.0)
    d.wait(0.8)
    ponto(d, "resultados")
    d.focus(66, 7, 70, dur=1.2)
    d.wait(1.0)
    d.key("right")
    d.key("down")
    d.key("down", hold=1.2)
    ponto(d, "resultados portas")
    d.focus(66, 15, 70, dur=1.2)
    d.wait(2.8)
    d.focus(50, 14, 104, dur=1.2)
    d.caption("Sem telemetria · sem shell · 100% local")
    d.wait(2.4)


def configurar(d):
    """Cada opção explicada, comando ao vivo, busca global."""
    d.wait(1.0)
    d.caption("Mais de 110 opções do nmap, todas explicadas em português")
    d.click_text("Configurar", dur=1.0)
    d.wait(1.0)
    d.click_text("Serviços e SO", dur=0.9)
    d.focus(70, 9, 58, dur=1.2)
    d.wait(0.8)
    d.caption("O que faz · quando usar · cuidado")
    d.wait(2.4)
    d.key("enter")
    ponto(d, "sV ligado")
    d.focus(30, 25, 60, dur=1.1)
    d.caption("O comando muda na hora")
    d.wait(2.2)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("Velocidade: do paranoico ao insano, com a explicação de cada nível")
    d.click_text("Tempo", dur=0.9)
    d.focus(50, 14, 104, dur=1.0)
    for _ in range(5):
        d.key("enter", hold=0.7)
    ponto(d, "tempo T4")
    d.focus(30, 25, 60, dur=1.1)
    d.wait(1.8)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("Não sabe onde fica? Busque por nome, flag ou o que faz")
    d.key("/")
    d.type("udp", cps=6)
    d.wait(0.4)
    ponto(d, "busca")
    d.focus(50, 11, 84, dur=1.2)
    d.wait(2.2)
    d.key("down")
    d.key("enter")
    d.wait(0.8)
    d.focus(35, 9, 70, dur=1.2)
    ponto(d, "salto")
    d.wait(2.0)

    d.focus(50, 14, 104, dur=1.0)
    d.caption("Tudo isso vira um comando de verdade, explicado por partes")
    d.click_text("Comando", dur=0.9)
    d.focus(34, 9, 70, dur=1.3)
    d.wait(3.6)
    d.focus(50, 14, 104, dur=1.0)
    d.wait(1.4)


def seguranca(d):
    """Avisos antes de executar e aviso de alvo externo (nada é escaneado)."""
    d.wait(1.0)
    d.caption("Segurança na frente: o nscope confere antes de executar")
    d.wait(2.0)
    d.click_text("Configurar", dur=1.0)
    d.click_text("Técnica", dur=0.8)
    d.focus(30, 6, 60, dur=1.2)
    d.key("down")
    d.key("enter")  # liga o scan UDP
    d.wait(0.8)
    d.focus(50, 14, 104, dur=1.0)
    d.caption("Avisos de privilégio, conflito e risco aparecem antes de rodar")
    d.click_text("Comando", dur=0.9)
    d.wait(0.6)
    d.focus(75, 12, 56, dur=1.3)
    ponto(d, "avisos")
    d.wait(3.6)

    d.focus(50, 14, 104, dur=1.0)
    d.click_text("Configurar", dur=0.9)
    d.wait(0.4)
    d.key("enter")  # desliga o UDP de novo
    d.wait(0.6)
    d.caption("Alvo fora da sua rede? A aba Alvo avisa")
    d.click_text("Alvo", dur=0.9)
    d.key("enter")
    apagar(d, 20)
    d.type("8.8.8.8", cps=7)
    d.key("enter")
    d.wait(0.8)
    ponto(d, "aviso alvo externo")
    d.focus(50, 5, 80, dur=1.3)
    d.caption("Só escaneie com autorização: aqui nada é executado (sem r)")
    d.wait(4.0)
    # volta ao alvo de prática para nenhum r posterior ir para a rede de terceiros
    d.key("enter")
    apagar(d, 20)
    d.type("scanme.nmap.org", cps=10)
    d.key("enter")
    d.focus(50, 14, 104, dur=1.1)
    d.caption("Nada foi enviado à rede")
    d.wait(2.6)


def capturas(d):
    """Uma imagem estática por aba, para a galeria do README."""
    out = {}
    d.wait(1.0)
    for tecla, nome in [("1", "alvo"), ("2", "perfis"), ("3", "configurar"), ("4", "comando"), ("8", "ajuda")]:
        d.key(tecla, hold=0.6, show=False)
        out[nome] = len(d.frames) - 1
    return out


ROTEIROS = {"fluxo": fluxo, "configurar": configurar, "seguranca": seguranca}


def gravar(nome, reusar):
    """Grava o roteiro (ou recarrega a gravação do cache) e devolve os quadros."""
    cache = os.path.join(tempfile.gettempdir(), f"nscope-demo-{nome}.pkl")
    if reusar and os.path.exists(cache):
        with open(cache, "rb") as f:
            return pickle.load(f)
    d = novo()
    try:
        ROTEIROS[nome](d)
    finally:
        d.close()
    with open(cache, "wb") as f:
        pickle.dump(d.frames, f)
    return d.frames


def salvar_capturas():
    d = novo()
    try:
        abas = capturas(d)
        for aba, i in abas.items():
            rec = dict(d.frames[i], mouse=(-50, -50), key="", caption="", cap_alpha=0.0, cam=d._box(None))
            engine.still_png(rec, os.path.join(MEDIA, f"tela-{aba}.png"))
            print("ok", aba)
    finally:
        d.close()


def main():
    nomes = [a for a in sys.argv[1:] if not a.startswith("--")] or [*ROTEIROS, "capturas"]
    os.makedirs(MEDIA, exist_ok=True)
    for nome in nomes:
        if nome == "capturas":
            salvar_capturas()
            continue
        frames = gravar(nome, "--reusar" in sys.argv)
        print(f"{nome}: {len(frames)} quadros ({len(frames) / engine.FPS:.1f}s)")
        if "--texto" in sys.argv:
            print("\n".join(LOG))
            continue
        engine.encode(frames, mp4=os.path.join(MEDIA, f"{nome}.mp4"), gif=os.path.join(MEDIA, f"{nome}.gif"),
                      gif_width=640, gif_fps=10, gif_colors=48)
        print("gerado:", nome)


if __name__ == "__main__":
    main()
