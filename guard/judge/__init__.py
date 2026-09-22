"""The judge stage (Stage 2): consulted only when Stage 1 (guard.engine, deterministic) found no hard rule
and no proven allow, and the remaining signals are soft. It answers allow / block / escalate from a strict
schema (schema.py); an "allow" may name one repair from a closed menu (guard.repairs), never free text. It
can never override a Stage 1 decision -- see guard.engine.GuardDefense._consult_judge, the only call site.
"""
