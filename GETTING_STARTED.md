# Démarrage rapide — après le clone

Ce guide explique, étape par étape, quoi faire une fois le dépôt cloné sur une machine pour la première
fois. Il ne remplace pas le [README.md](README.md) (qui reste la référence technique) — c'est juste le
chemin le plus court pour vérifier que tout marche, puis lancer le service.

## 0. Ce que c'est

`agent-tool-call-guard` est la défense qu'on place entre l'agent SENTINEL et ses outils. Elle répond
`allow | block | escalate | rewrite` pour chaque action. Deux étapes:

- **Étape 1** (toujours active): des règles Python déterministes, pas de modèle, pas de réseau.
- **Étape 2** (optionnelle, désactivée par défaut): un petit LLM local (via [Ollama](https://ollama.com)),
  consulté seulement quand l'étape 1 n'a pas pu trancher.

## 1. Récupérer le code

```bash
git clone https://github.com/MaherAy/agent-tool-call-guard.git
cd agent-tool-call-guard
```

Le Stage 2 (le juge LLM) est encore sur une branche, pas encore fusionnée dans `main`. Pour l'avoir:

```bash
git checkout stage2-judge
```

(Une fois que la pull request https://github.com/MaherAy/agent-tool-call-guard/pull/new/stage2-judge est
mergée, cette étape ne sera plus nécessaire — `git checkout main` suffira.)

## 2. Installer Python et les dépendances

Il faut **Python 3.12 ou plus récent**. Vérifie avec `python3 --version` (ou `python --version` sous
Windows).

Crée un environnement virtuel pour ne rien installer globalement:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows (PowerShell ou cmd)
```

Installe le projet et ses dépendances de dev:

```bash
pip install -e ".[dev]"
```

## 3. Vérifier que tout marche

```bash
pytest
```

Tu dois voir quelque chose comme `81 passed, 2 skipped`. Tout tourne **sans réseau** — même les tests de
l'étape 2 utilisent un faux juge, pas de vrai appel à Ollama. Si un test échoue, ne continue pas: dis-le
avant d'aller plus loin.

## 4. Lancer le service (étape 1 seule, sans LLM)

```bash
uvicorn guard.app:app --port 8080
```

Vérifie qu'il répond:

```bash
curl http://127.0.0.1:8080/healthz
# -> {"status":"ok"}
```

C'est suffisant pour tester contre le kit SENTINEL (section 6). Pas besoin d'Ollama pour ça — le service
répond juste sans jamais consulter l'étape 2 (les cas ambigus tombent sur une règle de repli, sans appel
réseau).

## 5. (Optionnel) Activer l'étape 2 — le juge LLM

Seulement si tu veux tester le juge lui-même, ou si tu prépares les mesures finales.

```bash
# installe Ollama : https://ollama.com/download
ollama pull qwen3:1.7b
ollama serve                      # dans un terminal séparé, le laisser tourner

# dans le terminal du projet :
export GUARD_JUDGE_ENABLED=true   # Linux/macOS
# $env:GUARD_JUDGE_ENABLED="true" # Windows PowerShell
GUARD_TRACE_DIR=./trace uvicorn guard.app:app --port 8080
```

Sans `GUARD_JUDGE_ENABLED=true`, le service ne parle **jamais** à Ollama, même si Ollama tourne à côté —
c'est voulu, pour ne jamais faire un appel réseau surprise.

`GUARD_TRACE_DIR=./trace` enregistre une trace locale de chaque décision (utile pour comprendre pourquoi
le service a répondu quelque chose). Vérifier qu'elle n'a pas été trafiquée:

```bash
python -m guard.trace verify ./trace/guard-trace.jsonl
```

## 6. Tester contre le kit SENTINEL

Il faut un checkout séparé du kit officiel, à jour (`git pull` dedans — le kit a changé plusieurs fois
cette semaine, dernière mise à jour: extension de deadline au 23/09, support d'Ollama pour l'agent
lui-même).

```bash
cd ../Sentinel_Starter_Kit        # adapte le chemin
git pull
uv sync

uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080
```

Le service de la défense (étape 4) doit tourner dans un autre terminal pendant cette commande.

Pour évaluer sur tous les scénarios publiés d'un coup:

```bash
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > resultats.json
```

## 7. Problèmes fréquents

| Symptôme | Cause probable |
|---|---|
| `pip install` échoue sur la version de Python | il faut Python **3.12+**, vérifie avec `python3 --version` |
| `pytest` échoue tout de suite à l'import | l'environnement virtuel n'est pas activé, ou `pip install -e ".[dev]"` n'a pas été relancé après un `git pull` |
| Le service démarre mais `curl /healthz` ne répond pas | un autre programme occupe déjà le port 8080 — change de port avec `--port 8081` |
| `GUARD_JUDGE_ENABLED=true` mais les décisions ambiguës restent lentes ou échouent | Ollama n'est pas lancé (`ollama serve`), ou le modèle n'est pas encore téléchargé (`ollama pull qwen3:1.7b`) |
| L'agent (Qwen3-8B via Ollama) et le juge (qwen3:1.7b) tournent ensemble et tout devient très lent | pas assez de VRAM pour garder les deux modèles chargés en même temps — vérifie avec `ollama ps` |

## 8. Pour aller plus loin

- [README.md](README.md): comment chaque règle décide, ce que fait le juge en détail, les limites connues.
- [docs/existing_work_and_benchmark.md](docs/existing_work_and_benchmark.md): comparaison avec d'autres
  défenses SENTINEL publiques.
- Une question bloquante: mieux vaut demander avant de pousser du code cassé — le dépôt est partagé par
  toute l'équipe.
