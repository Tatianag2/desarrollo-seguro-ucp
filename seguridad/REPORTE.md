# Informe de seguridad — Lab Log4Shell

| | |
|---|---|
| **Alumno** | Tatiana García Grajales (@Tatianag2) y Javier Alejandro Vargas (@javargasp26) |
| **Fecha** | 2026-11-26 11:05 |
| **Repositorio** | Tatianag2/desarrollo-seguro-ucp |
| **Rama** | `feature/log4shell-demo` |
| **Herramientas** | gitleaks · semgrep · osv-scanner · trivy + IA (`openai/gpt-oss-120b`) |

## 1. Vulnerabilidad descubierta

El escaneo de dependencias (SCA) detectó **Log4Shell — CVE-2021-44228** en
`org.apache.logging.log4j:log4j-core@2.14.1`: ejecución remota de código (RCE)
crítica cuando la aplicación registra texto controlado por el atacante.

**Hallazgos del gate (antes del parche):** 18 — veredicto **🚫 BLOQUEADO** (exit 1)

| Herramienta | Severidad | Regla / CVE | Ubicacion |
|---|---|---|---|
| deps | HIGH | GHSA-qv9r-c865-cp47 | org.apache.logging.log4j:log4j-api@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-3pxv-7cmr-fjr4 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-6hg6-v5c8-fphq | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-7rjr-3q55-vv33 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-8489-44mv-ggj8 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-h383-gmxw-35v2 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-jfh8-c2jp-5v3q | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-p6xc-xr62-6r2g | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-vc5p-v9hr-52mj | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| trivy | MEDIUM | CVE-2026-49844 | org.apache.logging.log4j:log4j-api@2.14.1 |
| trivy | CRITICAL | CVE-2021-44228 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | CRITICAL | CVE-2021-45046 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | HIGH | CVE-2021-45105 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2021-44832 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2025-68161 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34477 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34479 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34480 | org.apache.logging.log4j:log4j-core@2.14.1 |

## 2. Análisis con IA

### 🤖 Explicacion y remediacion (IA)

**Riesgo principal:** La versión 2.14.1 de Log4j contiene vulnerabilidades críticas (Log4Shell) que permiten ejecución remota de código y denegación de servicio.

- **GHSA‑qv9r‑c865‑cp47 (log4j‑api 2.14.1)** – vulnerabilidad de deserialización que puede ser explotada vía mensajes de registro.  
  **Arreglo:** actualizar `log4j-api` a la última 2.x (p.ej. 2.26.1).

- **GHSA‑3pxv‑7cmr‑fjr4, GHSA‑6hg6‑v5c8‑fphq, GHSA‑7rjr‑3q55‑vv33, GHSA‑8489‑44mv‑ggj8, GHSA‑h383‑gmxw‑35v2, GHSA‑jfh8‑c2jp‑5v3q, GHSA‑p6xc‑xr62‑6r2g, GHSA‑vc5p‑v9hr‑52mj (log4j‑core 2.14.1)** – cubren CVE‑2021‑44228, CVE‑2021‑45046, CVE‑2021‑45105, CVE‑2021‑44832 y otras vulnerabilidades de RCE, bypass de filtros y DoS.  
  **Arreglo:** actualizar `log4j-core` a la última versión estable 2.x (≥ 2.26.1).

- **CVE‑2021‑44228** – “Log4Shell”, ejecución remota de código mediante la variable `${jndi}`.  
  **Arreglo:** subir `log4j-core` a ≥ 2.17.1 y, mejor, a la última 2.x (2.26.1+).

- **CVE‑2021‑45046** – permite evadir la mitigación de 44228 y ejecutar código arbitrario.  
  **Arreglo:** mismo upgrade que arriba.

- **CVE‑2021‑45105** – denegación de servicio por bucle de recursión en patrones de log.  
  **Arreglo:** upgrade a ≥ 2.17.1 (última 2.x).

- **CVE‑2021‑44832, CVE‑2025‑68161, CVE‑2026‑49844, CVE‑2026‑34477/34479/34480** – vulnerabilidades de deserialización y fuga de información en versiones antiguas.  
  **Arreglo:** actualizar a la última 2.x.

**Paso concreto:**  
En `pom.xml` reemplaza:

```xml
<log4j-api.version>2.14.1</log4j-api.version>
<log4j-core.version>2.14.1</log4j-core.version>
```

por:

```xml
<log4j-api.version>2.26.1</log4j-api.version>
<log4j-core.version>2.26.1</log4j-core.version>
```

Ejecuta `mvn clean install` y verifica que el escáner ya no reporte CVEs.

## 3. Remediación aplicada

Se actualizó `log4j-api` y `log4j-core` a **2.26.1** en `pom.xml`.

> **Lección:** 2.17.1 corrige los CVE de 2021, pero el escaneo aún marcaba CVEs
> de 2025/2026 en log4j; por eso no basta y se sube a la última 2.x estable (2.26.1).

**Hallazgos del gate (después del parche):** 0 — veredicto **✅ PASA** (exit 0)

_Sin hallazgos._

## 4. Evidencia

- Pull Request y corridas del gate (rojo → verde) en GitHub Actions del repo Tatianag2/desarrollo-seguro-ucp.
- Este informe: `seclab/ci-demo-app/REPORTE.md` (en el repo) + subido a **Moodle**.

## Conclusión

El pipeline **bloqueó el merge** hasta corregir la dependencia; la **IA** explicó el
riesgo y la remediación. El gate se re-evalúa contra bases de vulnerabilidades
actualizadas, por eso un fix "histórico" (2.17.1) puede no bastar hoy.

---
_Generado con `seclab/bin/informe.sh` el 2026-11-26 11:05._
