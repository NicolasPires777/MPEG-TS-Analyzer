# Analisador de Continuidade de Pacotes MPEG-TS

Este script em Python tem como objetivo analisar arquivos `.pcap` (MPEG Transport Stream) e verificar a continuidade dos pacotes com base no campo **Continuity Counter (CC)**. Ele é útil para detectar falhas ou descontinuidades em fluxos TS, especialmente no contexto de emissoras de televisão.

## 🚀 Funcionalidades

- Analisa pacotes MPEG-TS.
- Detecta e reporta descontinuidades por PID.
- Exibe estatísticas gerais da análise.
- Mostra tempo aproximado de ocorrência das falhas.

## 📁 Estrutura esperada

O script espera arquivos `.pcap` válidos, com pacotes MPEG-TS de **188 bytes**. Pode ser usado diretamente com arquivos gerados por ferramentas como `tcpdump`, `tsudpsend`, `tsloop`, etc.

## 🧪 Requisitos

- Python 3.x
- Scapy

## ▶️ Como usar

- Preencha as linhas 4 e 5 de `analyzer.py` com o arquivo pcap e o IP de destino dos pacotes MPEG TS
- Rode a aplicação com `python analyzer.py`
