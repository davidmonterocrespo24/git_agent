import os
import re
import glob
import json
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import ast, tempfile


from git import Repo
from github import Github
import textwrap
from slugify import slugify  # pip install python-slugify
import datetime as _dt
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from langchain.agents import AgentType, initialize_agent, tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage

# ────────────────────────────────
# 0. Configuración de logging
# ────────────────────────────────

# código (diff conceptual)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ────────────────────────────────
# 1. Cargar variables de entorno
# ────────────────────────────────
load_dotenv()
# https://github.com/davidmonterocrespo24/odoo_micro_saas
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "o3")  # Valor predeterminado mejorado

# Validación de variables de entorno
required_vars = {
    "GITHUB_TOKEN": GITHUB_TOKEN,
    "GITHUB_REPO_OWNER": GITHUB_REPO_OWNER,
    "GITHUB_REPO_NAME": GITHUB_REPO_NAME,
    "OPENAI_API_KEY": OPENAI_API_KEY,
}
for var_name, value in required_vars.items():
    if not value:
        raise RuntimeError(f"Variable {var_name} no definida en .env")
def _is_valid_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False

# ────────────────────────────────
# 2. Herramienta de análisis de código
# ────────────────────────────────
SYSTEM_TEMPLATE = """
Eres un experto analista de código Python con amplia experiencia en optimización, seguridad y buenas prácticas.

TAREA:
Analiza el código Python proporcionado y detecta problemas en estas categorías:
1. ERROR: Errores lógicos, bugs o comportamientos incorrectos
2. PERFORMANCE: Ineficiencias o cuellos de botella en el rendimiento
3. IMPROVEMENT: Oportunidades para mejorar legibilidad, mantenibilidad o seguir PEP8
4. SECURITY: Vulnerabilidades de seguridad o prácticas inseguras

IMPORTANTE: Devuelve EXCLUSIVAMENTE un JSON válido siguiendo con precisión este esquema:

{
  "issues": [
    {
      "type": "ERROR|PERFORMANCE|IMPROVEMENT|SECURITY",
      "title": "Título corto y descriptivo",
      "line_number": número_de_línea,
      "description": "Descripción detallada que explique por qué esto es un problema y su impacto",
      "original_code": "Código original o fragmento relevante",
      "solution": "Solo el código de reemplazo.NO incluyas comentarios o texto explicativo.Mantén la misma indentación que el fragmento original.",
      "diff": "Código (diff conceptual)",
      "severity": "HIGH|MEDIUM|LOW" 
    }
  ]
}

La severidad debe asignarse según estas reglas:
- HIGH: Problemas críticos que podrían causar fallos, pérdida de datos o vulnerabilidades graves
- MEDIUM: Problemas importantes que afectan el rendimiento o la calidad del código
- LOW: Mejoras menores o sugerencias de optimización

Si no encuentras problemas significativos, responde exactamente con:
{ "issues": [] }

NO incluyas explicaciones adicionales ni texto fuera del JSON.
"""


class PRPayload(BaseModel):
    title: str = Field(...)
    body: str = Field(...)
    head_branch: str = Field(..., description="Rama que contiene los cambios")
    base_branch: str = Field(default="main")


@tool(
    "github_pr_creator",
    args_schema=PRPayload,
    return_direct=True,
    description="Crea un Pull-Request en GitHub y devuelve su URL",
)
def github_pr_creator(
    title: str, body: str, head_branch: str, base_branch: str = "main"
) -> str:
    try:
        gh = Github(GITHUB_TOKEN)
        repo = gh.get_repo(f"{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
        pr = repo.create_pull(
            title=title, body=body, head=head_branch, base=base_branch, draft=False
        )
        logger.info(f"PR creado: {pr.html_url}")
        return pr.html_url
    except Exception as e:
        logger.error(f"Error al crear PR: {e}")
        return f"Error al crear PR: {e}"


class AnalyzerInput(BaseModel):
    file_path: str = Field(description="Ruta absoluta al archivo .py")
    code: str = Field(description="Contenido completo del archivo .py")


@tool(
    "code_analyzer",
    args_schema=AnalyzerInput,
    return_direct=True,
    description="Analiza código Python y devuelve JSON con los problemas",
)
def code_analyzer(file_path: str, code: str) -> str:
    """
    Analiza código Python para identificar problemas de lógica, rendimiento, seguridad y buenas prácticas.

    Args:
        code_and_path: String con formato "<file_path>\n<<<CODE>>>\n<code_content>"

    Returns:
        Un JSON (str) con los problemas encontrados o un objeto vacío si no hay problemas.
    """
    try:
        file_name = os.path.basename(file_path)
        logger.info(f"Analizando archivo: {file_name}")
    except ValueError:
        logger.error("Formato incorrecto en la entrada de code_analyzer")
        return json.dumps({"issues": [], "error": "Formato recibido incorrecto"})

    try:
        llm = ChatOpenAI(model=MODEL_NAME, api_key=OPENAI_API_KEY)

        messages = [
            SystemMessage(content=SYSTEM_TEMPLATE),
            SystemMessage(content=f"Archivo: {file_path}\n```python\n{code}\n```"),
        ]

        response = llm.invoke(messages)

        # Extraer solo el JSON de la respuesta
        match = re.search(r"\{[\s\S]*\}", response.content)
        if match:
            result = match.group(0)
            # Validar que sea un JSON bien formado
            json.loads(result)  # Esto lanzará una excepción si no es JSON válido
            return result

        logger.warning(f"No se encontró JSON en la respuesta para {file_name}")
        return json.dumps({"issues": []})

    except Exception as e:
        logger.error(f"Error durante el análisis de {file_name}: {str(e)}")
        return json.dumps({"issues": [], "error": f"Error: {str(e)}"})


# ────────────────────────────────
# 3. Herramienta para crear issues en GitHub
# ────────────────────────────────
@tool(
    "github_issue_creator",
    return_direct=True,
    args_schema=None,
    description="Crea un issue en GitHub y devuelve la URL",
)
def github_issue_creator(payload: str) -> str:
    """
    Crea un issue en GitHub basado en la información proporcionada.

    Args:
        payload: JSON con los campos title, body, y labels (opcional)

    Returns:
        URL del issue creado o mensaje de error
    """
    try:
        data = json.loads(payload)
        title = data["title"]
        body = data["body"]
        labels = data.get("labels", [])

        logger.info(f"Creando issue: {title}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error al parsear payload del issue: {e}")
        return f"Error: No se pudo procesar el payload ({e})"

    try:
        gh = Github(GITHUB_TOKEN)
        repo = gh.get_repo(f"{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
        issue = repo.create_issue(title=title, body=body, labels=labels)
        logger.info(f"Issue creado: {issue.html_url}")
        return issue.html_url
    except Exception as e:
        logger.error(f"Error al crear issue en GitHub: {e}")
        return f"Error al crear issue: {str(e)}"


# ────────────────────────────────
# 4. Clase principal del analizador
# ────────────────────────────────
class GitRepoAnalyzer:
    """
    Clase para analizar un repositorio Git, identificar problemas en el código
    y crear issues en GitHub para cada problema encontrado.
    """

    def __init__(self, repo_path: str, target_folder: str):
        """
        Inicializa el analizador de repositorios.

        Args:
            repo_path: Ruta al repositorio local
            target_folder: Carpeta dentro del repositorio a analizar
        """
        self.repo_path = repo_path
        self.target_folder = target_folder

        # Validar que el repo sea un repositorio Git válido
        try:
            self.repo = Repo(repo_path)
        except Exception as e:
            raise ValueError(f"No se pudo inicializar el repositorio Git: {e}")

        # Inicializar el agente de LangChain
        self.agent = initialize_agent(
            tools=[code_analyzer, github_issue_creator, github_pr_creator],
            llm=ChatOpenAI(model=MODEL_NAME, api_key=OPENAI_API_KEY),
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=False,
            handle_parsing_errors=True,
        )

        logger.info(f"Analizador inicializado para {target_folder} en {repo_path}")

    def _detect_eol(self, file_path: str) -> str:
        with open(file_path, 'rb') as f:
            sample = f.read(8192)
        if b'\r\n' in sample:
            return '\r\n'
        return '\n'
    
    # Métodos de utilidad para enlaces a GitHub
    def _commit_sha(self) -> str:
        """Obtiene el SHA del commit actual en la rama actual"""
        return self.repo.head.commit.hexsha

    def _file_url(self, file_path: str) -> str:
        """
        Genera URL de GitHub para un archivo en el commit actual

        Args:
            file_path: Ruta absoluta al archivo

        Returns:
            URL de GitHub para el archivo
        """
        rel_path = os.path.relpath(file_path, self.repo_path)
        return f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/blob/{self._commit_sha()}/{rel_path}"

    def _line_url(self, file_path: str, line_number: int) -> str:
        """
        Genera URL de GitHub para una línea específica en un archivo

        Args:
            file_path: Ruta absoluta al archivo
            line_number: Número de línea

        Returns:
            URL de GitHub con ancla a la línea específica
        """
        return f"{self._file_url(file_path)}#L{line_number}"

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analiza un archivo Python individual y crea issues para los problemas encontrados

        Args:
            file_path: Ruta absoluta al archivo Python

        Returns:
            Lista de diccionarios con información de los issues creados
        """
        logger.info(f"Analizando archivo: {os.path.basename(file_path)}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Error al leer archivo {file_path}: {e}")
            return []

        # Preparar input para el analizador
        input_str = f"{file_path}\n<<<CODE>>>\n{code}"

        try:
            # Invocar agente para ejecutar code_analyzer
            response = self.agent.invoke(
                {"input": f"Analiza este archivo:\n{input_str}"}
            )
            if isinstance(response, dict):
                res_json = response.get("output", "")
            else:
                res_json = response
            try:
                issues_dict = json.loads(res_json)
            except json.JSONDecodeError:
                logger.error(f"Respuesta no es JSON válido: {res_json[:80]}...")
                return []
            issues = issues_dict.get("issues", [])

            if not issues:
                logger.info(
                    f"No se encontraron problemas en {os.path.basename(file_path)}"
                )
                return []

            logger.info(
                f"Se encontraron {len(issues)} problemas en {os.path.basename(file_path)}"
            )
        except Exception as e:
            logger.error(f"Error durante el análisis: {e}")
            return []

        created_issues = []
        for issue in issues:
            try:
                # Construir cuerpo del issue con formato mejorado
                file_name = os.path.basename(file_path)
                line_url = self._line_url(file_path, issue["line_number"])

                body = f"""
## Problema detectado por IA

**Archivo:** [{file_name}]({line_url})  
**Línea:** {issue['line_number']}  
**Tipo:** {issue['type']}  
**Severidad:** {issue['severity']}

### Descripción
{issue['description']}

### Código original
```python
{issue['original_code']}
```

### Solución propuesta
```python
{issue['solution']}
```

### Diff conceptual
```diff
{issue['diff']}
```

---
*Este issue fue generado automáticamente por un análisis de código con IA*
"""

                gh = Github(GITHUB_TOKEN)
                repo = gh.get_repo(f"{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")

                issue_obj = repo.create_issue(
                    title=f"[{issue['type']}][{issue['severity']}] {issue['title']}",
                    body=body,
                    labels=[
                        issue["type"].lower(),
                        f"severity:{issue['severity'].lower()}",
                        "ai-detected",
                    ],
                )
                issue_number = issue_obj.number
                issue_url = issue_obj.html_url
                logger.info(f"Issue creado: {issue_url}")

                # ---------- 2) si NO es HIGH, pasamos al siguiente ------------
                if issue["severity"].upper() != "HIGH":
                    created_issues.append({"url": issue_url, **issue})
                    continue

                # ---------- 3) crear rama, commit y push ----------------------
                branch = self._create_branch_name(issue["title"])
                try:
                    self._apply_patch(
                        file_path, issue["line_number"],  issue["original_code"],issue["solution"]
                    )
                    self._commit_and_push(
                        branch,
                        [os.path.relpath(file_path, self.repo_path)],
                        f"fix: {issue['title']} (auto-generated by IA)",
                    )
                except Exception as e:
                    logger.error(f"No se pudo hacer push de la rama: {e}")
                    issue_obj.create_comment(
                        f"❌ Error al crear la rama/commit automático: {e}"
                    )
                    continue

                # ---------- 4) crear Pull-Request -----------------------------
                pr_title = f"AI FIX: {issue['title']}"
                pr_body = (
                    f"Closes #{issue_number}\n\n"
                    "Aplicada la solución sugerida por la IA."
                )
                pr_url = github_pr_creator.invoke(
                    title=pr_title,
                    body=pr_body,
                    head_branch=branch,
                    base_branch="main",
                )
                logger.info(f"PR creado: {pr_url}")

                # ---------- 5) comentar el issue con los enlaces --------------
                issue_obj.create_comment(
                    f"🚀 Se ha abierto el Pull-Request **[{pr_title}]({pr_url})**\n"
                    f"Rama: `{branch}`"
                )

                created_issues.append(
                    {"url": issue_url, "pr_url": pr_url, "branch": branch, **issue}
                )

            except Exception as e:
                logger.error(f"Error al crear issue: {e}")

        return created_issues

    def analyze_folder(self):
        """
        Analiza todos los archivos Python en la carpeta objetivo y crea issues para los problemas.
        """
        folder_abs = os.path.join(self.repo_path, self.target_folder)
        py_files = glob.glob(f"{folder_abs}/**/*.py", recursive=True)

        if not py_files:
            logger.warning(f"No se encontraron archivos Python en {self.target_folder}")
            print(f"⚠️ No se encontraron archivos Python en {self.target_folder}")
            return

        logger.info(
            f"Analizando {len(py_files)} archivos Python en {self.target_folder}"
        )
        print(f"🔍 Encontrados {len(py_files)} archivos Python para analizar")

        # Analizar cada archivo y registrar resultados
        file_summaries = {}
        total_issues = 0

        for path in py_files:
            file_name = os.path.basename(path)
            print(f"🔍 Analizando {file_name}...")

            issues = self.analyze_file(path)
            if issues:
                rel_path = os.path.relpath(path, self.repo_path)
                file_summaries[rel_path] = {
                    "issues": issues,
                    "issues_count": len(issues),
                }
                total_issues += len(issues)
                print(f"⚠️ Se encontraron {len(issues)} problemas en {file_name}")
            else:
                print(f"✅ No se encontraron problemas en {file_name}")

        # Crear issue de resumen si se encontraron problemas
        if file_summaries:
            logger.info(
                f"Creando resumen para {len(file_summaries)} archivos con problemas"
            )
            print(
                f"\n📊 Creando resumen para {len(file_summaries)} archivos con {total_issues} problemas en total"
            )
            self.create_summary_issue(file_summaries)
        else:
            logger.info("No se encontraron problemas en ningún archivo")
            print("\n✅ ¡No se encontraron problemas en ningún archivo analizado!")

    def create_summary_issue(self, file_summaries: Dict[str, Dict[str, Any]]):
        """
        Crea un issue de resumen que compila todos los problemas encontrados

        Args:
            file_summaries: Diccionario con información de issues por archivo
        """
        print(f"🔍 Creando issue de resumen...")
        logger.info(f"Intentando crear issue resumen para {self.target_folder}")
        logger.debug(f"Tamaño del cuerpo del issue resumen: {len(body)} caracteres")
#
        total_issues = sum(d["issues_count"] for d in file_summaries.values())

        # Construir cuerpo del issue con formato mejorado
        body = f"""# 📑 Informe de Análisis con IA: `{self.target_folder}`

## Resumen Ejecutivo
- **Fecha de análisis:** {os.popen('date').read().strip()}
- **Commit analizado:** [`{self._commit_sha()[:7]}`](https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commit/{self._commit_sha()})
- **Archivos con problemas:** **{len(file_summaries)}**
- **Total de problemas detectados:** **{total_issues}**

## 📋 Detalle por archivo
"""
        # Contadores para estadísticas
        issues_by_type = {}
        issues_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Agregar detalles por archivo
        for file_rel, data in sorted(file_summaries.items()):
            file_url = self._file_url(os.path.join(self.repo_path, file_rel))
            body += f"\n### [{file_rel}]({file_url})\n"
            print(f"🔍 Analizando {file_rel}...")

            # Agrupar issues por tipo en este archivo
            file_issues_by_type = {}
            for issue in data["issues"]:
                issue_type = issue["type"]
                if issue_type not in file_issues_by_type:
                    file_issues_by_type[issue_type] = []
                file_issues_by_type[issue_type].append(issue)

                # Actualizar contadores globales
                issues_by_type[issue_type] = issues_by_type.get(issue_type, 0) + 1
                issues_by_severity[issue["severity"]] += 1

            # Mostrar issues agrupados por tipo
            for issue_type, issues_list in file_issues_by_type.items():
                body += f"**{issue_type}:**\n"
                for issue in issues_list:
                    body += (
                        f"- [{issue['title']}]({issue['url']}) ({issue['severity']})\n"
                    )

            body += "\n"

        # Agregar estadísticas
        body += "\n## 📊 Estadísticas\n"

        # Por tipo
        body += "\n### Por tipo de problema\n"
        for issue_type, count in sorted(
            issues_by_type.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_issues) * 100
            body += f"- **{issue_type}:** {count} ({percentage:.1f}%)\n"

        # Por severidad
        body += "\n### Por nivel de severidad\n"
        for severity, count in sorted(
            issues_by_severity.items(),
            key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x[0]],
        ):
            if count > 0:
                percentage = (count / total_issues) * 100
                body += f"- **{severity}:** {count} ({percentage:.1f}%)\n"

        # Recomendaciones finales
        body += """
## 🔍 Próximos pasos recomendados

1. Revisar cada issue individualmente, empezando por los de severidad HIGH
2. Aplicar las correcciones sugeridas o implementar soluciones alternativas
3. Ejecutar pruebas para verificar que las soluciones no introduzcan nuevos problemas
4. Considerar agregar pruebas automatizadas para evitar regresiones

---
*Este informe fue generado automáticamente mediante análisis de código con IA*
"""

        # Crear el issue de resumen
        payload = {
            "title": f"📊 Informe global IA: {self.target_folder}",
            "body": body,
            "labels": ["summary", "ai-analysis", "technical-debt"],
        }

        print(f"🔍 Creando issue de resumen...")
        print(f"📌 Payload del issue de resumen: {json.dumps(payload, indent=2)}")
        try:
            url = self.agent.invoke(
                {
                    "input": f"Crea un issue resumen con este payload:\n```json\n{json.dumps(payload)}\n```"
                }
            ).get("output", "")

            if url and not url.startswith("Error"):
                logger.info(f"Issue de resumen creado: {url}")
                print(f"📌 Issue resumen creado: {url}")
            else:
                logger.error(f"Error al crear issue de resumen: {url}")
                print("❌ No se pudo crear el issue de resumen")
        except Exception as e:
            logger.error(f"Error al crear issue de resumen: {e}")
            print(f"❌ Error al crear issue de resumen: {e}")

    def _create_branch_name(self, issue_title: str) -> str:
        date = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        slug = slugify(issue_title)[:25]
        return f"ai/fix/{slug}-{date}"

    def _apply_patch(self, file_path: str, line_num: int, original_code: str, new_code: str):
        # 1) leer preservando fin de línea exacto
        eol = self._detect_eol(file_path)
        original_indent = re.match(r"\s*", lines[idx]).group(0) if idx < len(lines) else "" # Asegurar idx válido

        try:
            # Usar encoding='utf-8' explícitamente es buena práctica
            with open(file_path, "r", newline='') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error al leer {file_path} para aplicar patch: {e}")
            raise  # Re-lanzar la excepción para que el proceso falle limpiamente

        # Asegurarse que el número de línea es válido
        if line_num <= 0 or line_num > len(lines):
             logger.error(f"Número de línea inválido ({line_num}) para archivo {file_path} con {len(lines)} líneas.")
             # Decide cómo manejar este error: ¿continuar, lanzar excepción?
             # Por ahora, lanzamos una excepción para detener el proceso para este issue.
             raise ValueError(f"Número de línea inválido: {line_num}")

        idx = line_num - 1 # Índice base 0

        # --- INICIO CAMBIO ---
        # Calcular cuántas líneas ocupa el código original detectado
        # Se usa splitlines() para manejar correctamente diferentes EOLs al contar
        # Se añade un fallback a 1 si original_code está vacío o es None por alguna razón
        num_original_lines = len(original_code.splitlines()) if original_code else 1
        # Asegurarse de no intentar reemplazar más allá del final del archivo
        num_original_lines = min(num_original_lines, len(lines) - idx)
        if num_original_lines <= 0:
             num_original_lines = 1 # Como mínimo, reemplazar la línea indicada por line_num

        logger.info(f"Aplicando parche en {os.path.basename(file_path)}:{line_num}. Reemplazando {num_original_lines} línea(s).")
        # --- FIN CAMBIO ---


        # 2) mantener indentación original (de la PRIMERA línea a reemplazar)
        original_indent = re.match(r"\s*", lines[idx]).group(0)
        if not _is_valid_python(new_code):
            logger.warning("El reemplazo proporcionado por la IA no parece ser código Python válido.")
            # Considera qué hacer aquí. ¿Marcar el issue? ¿No aplicar?
            # Por ahora, podrías añadir un TODO como tenías, o lanzar un error.
            #new_code = f"# TODO: Revisar código IA inválido:\n# {new_code.replace('\n', '\n# ')}"
            #new_code = + "\n"+original_code
            # O mejor, no aplicar el parche si no es válido:
            #raise ValueError("La solución propuesta por la IA no es código Python válido.")
            return False


        # Preparar las nuevas líneas con la indentación correcta y EOL original
        # Dedent limpia la indentación base de la solución de la IA.
        new_lines_content = textwrap.dedent(new_code).splitlines() # splitlines() quita EOLs

        prepared_new_lines = []
        if new_lines_content: # Si hay contenido nuevo
            for line in new_lines_content:
                # Aplica indentación original. No uses rstrip() aquí para preservar espacios finales intencionales.
                prepared_line = original_indent + line
                prepared_new_lines.append(prepared_line + eol) # Agrega el EOL detectado
        # Si new_lines_content está vacío, prepared_new_lines será [], eliminando las líneas originales.

        # 3) sustituir la REGIÓN correcta
        # Asegúrate que el slice no exceda los límites
        end_idx = min(idx + num_original_lines, len(lines))
        lines[idx : end_idx] = prepared_new_lines

        # 4) escribir con el EOL preservado por newline='' y UTF-8
        try:
            # Usa encoding='utf-8' explícito también al escribir
            with open(file_path, "w", encoding='utf-8', newline='') as f:
                f.writelines(lines)
            logger.info(f"Parche aplicado exitosamente a {os.path.basename(file_path)}:{line_num}.")
        except Exception as e:
            logger.error(f"Error al escribir el parche en {file_path}: {e}")
            raise # Re-lanzar para detener el proceso

    def _commit_and_push(self, branch: str, files_to_add: List[str], message: str):
        origin = self.repo.remote(name="origin")
        # Crea la rama local (si no existe)
        if branch not in self.repo.heads:
            self.repo.git.checkout("-b", branch)
        else:
            self.repo.git.checkout(branch)

        # Añadir y commitear
        self.repo.index.add(files_to_add)
        self.repo.index.commit(message)

        # Push (es necesario que origin use https://x-access-token:TOKEN@... o ssh-agent ya autorizado)
        origin.push(branch)


def main():
    """Función principal que ejecuta el análisis"""
    print("\n🔍 GitHub Issue Creator - Análisis de código 🔍\n")

    try:
        repo_path = input("Ruta al repositorio local: ").rstrip("/")
        target_folder = input("Carpeta a analizar (relativa al repo): ").rstrip("/")

        # Validar rutas
        if not os.path.isdir(repo_path):
            print(f"❌ La ruta {repo_path} no existe o no es un directorio")
            return

        folder_path = os.path.join(repo_path, target_folder)
        if not os.path.isdir(folder_path):
            print(f"❌ La carpeta {target_folder} no existe en el repositorio")
            return

        # Confirmar operación
        print(f"\n📁 Se analizará: {folder_path}")
        confirm = input("¿Continuar? (s/n): ").lower()
        if confirm != "s":
            print("❌ Operación cancelada")
            return

        # Ejecutar análisis
        print("\n🚀 Iniciando análisis...\n")
        analyzer = GitRepoAnalyzer(repo_path, target_folder)
        analyzer.analyze_folder()

        print("\n✅ Análisis completado!\n")

    except KeyboardInterrupt:
        print("\n❌ Operación interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Error en la ejecución principal")


if __name__ == "__main__":
    main()
