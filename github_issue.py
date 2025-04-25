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
# 0. Logging Configuration
# ────────────────────────────────

# code (conceptual diff)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ────────────────────────────────
# 1. Load Environment Variables
# ────────────────────────────────
load_dotenv()
# https://github.com/davidmonterocrespo24/odoo_micro_saas
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "o3")  # Improved default value

# Environment variables validation
required_vars = {
    "GITHUB_TOKEN": GITHUB_TOKEN,
    "GITHUB_REPO_OWNER": GITHUB_REPO_OWNER,
    "GITHUB_REPO_NAME": GITHUB_REPO_NAME,
    "OPENAI_API_KEY": OPENAI_API_KEY,
}
for var_name, value in required_vars.items():
    if not value:
        raise RuntimeError(f"Variable {var_name} not defined in .env")
def _is_valid_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False

# ────────────────────────────────
# 2. Code Analysis Tool
# ────────────────────────────────
SYSTEM_TEMPLATE = """
You are an expert Python code analyst with extensive experience in optimization, security, and best practices.

TASK:
Analyze the provided Python code and detect issues in these categories:
1. ERROR: Logical errors, bugs, or incorrect behaviors
2. PERFORMANCE: Inefficiencies or performance bottlenecks
3. IMPROVEMENT: Opportunities to improve readability, maintainability, or follow PEP8
4. SECURITY: Security vulnerabilities or unsafe practices

IMPORTANT: Return EXCLUSIVELY a valid JSON following this schema precisely:

{
  "issues": [
    {
      "type": "ERROR|PERFORMANCE|IMPROVEMENT|SECURITY",
      "title": "Short descriptive title",
      "line_number": line_number,
      "description": "Detailed description explaining why this is an issue and its impact",
      "original_code": "Original code or relevant fragment",
      "solution": "Only the replacement code. DO NOT include explanatory comments or text. Maintain the same indentation as the original fragment.",
      "diff": "Code (conceptual diff)",
      "severity": "HIGH|MEDIUM|LOW" 
    }
  ]
}

Severity should be assigned according to these rules:
- HIGH: Critical issues that could cause failures, data loss, or serious vulnerabilities
- MEDIUM: Important issues affecting performance or code quality
- LOW: Minor improvements or optimization suggestions

If you don't find significant issues, respond exactly with:
{ "issues": [] }

DO NOT include additional explanations or text outside the JSON.
"""


class PRPayload(BaseModel):
    title: str = Field(...)
    body: str = Field(...)
    head_branch: str = Field(..., description="Branch containing the changes")
    base_branch: str = Field(default="main")


@tool(
    "github_pr_creator",
    args_schema=PRPayload,
    return_direct=True,
    description="Creates a GitHub Pull-Request and returns its URL",
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
        logger.info(f"PR created: {pr.html_url}")
        return pr.html_url
    except Exception as e:
        logger.error(f"Error creating PR: {e}")
        return f"Error creating PR: {e}"


class AnalyzerInput(BaseModel):
    file_path: str = Field(description="Absolute path to the .py file")
    code: str = Field(description="Complete content of the .py file")


@tool(
    "code_analyzer",
    args_schema=AnalyzerInput,
    return_direct=True,
    description="Analyzes Python code and returns JSON with issues",
)
def code_analyzer(file_path: str, code: str) -> str:
    """
    Analyzes Python code to identify logical issues, performance, security and best practices.

    Args:
        code_and_path: String with format "<file_path>\n<<<CODE>>>\n<code_content>"

    Returns:
        A JSON (str) with the issues found or an empty object if no issues found.
    """
    try:
        file_name = os.path.basename(file_path)
        logger.info(f"Analyzing file: {file_name}")
    except ValueError:
        logger.error("Incorrect format in code_analyzer input")
        return json.dumps({"issues": [], "error": "Incorrect format received"})

    try:
        llm = ChatOpenAI(model=MODEL_NAME, api_key=OPENAI_API_KEY)

        messages = [
            SystemMessage(content=SYSTEM_TEMPLATE),
            SystemMessage(content=f"File: {file_path}\n```python\n{code}\n```"),
        ]

        response = llm.invoke(messages)

        # Extract only JSON from the response
        match = re.search(r"\{[\s\S]*\}", response.content)
        if match:
            result = match.group(0)
            # Validate that it's a well-formed JSON
            json.loads(result)  # This will raise an exception if not valid JSON
            return result

        logger.warning(f"No JSON found in response for {file_name}")
        return json.dumps({"issues": []})

    except Exception as e:
        logger.error(f"Error during analysis of {file_name}: {str(e)}")
        return json.dumps({"issues": [], "error": f"Error: {str(e)}"})


# ────────────────────────────────
# 3. Tool for creating GitHub issues
# ────────────────────────────────
@tool(
    "github_issue_creator",
    return_direct=True,
    args_schema=None,
    description="Creates a GitHub issue and returns the URL",
)
def github_issue_creator(payload: str) -> str:
    """
    Creates a GitHub issue based on the provided information.

    Args:
        payload: JSON with fields title, body, and labels (optional)

    Returns:
        URL of the created issue or error message
    """
    try:
        data = json.loads(payload)
        title = data["title"]
        body = data["body"]
        labels = data.get("labels", [])

        logger.info(f"Creating issue: {title}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error parsing issue payload: {e}")
        return f"Error: Could not process the payload ({e})"

    try:
        gh = Github(GITHUB_TOKEN)
        repo = gh.get_repo(f"{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
        issue = repo.create_issue(title=title, body=body, labels=labels)
        logger.info(f"Issue created: {issue.html_url}")
        return issue.html_url
    except Exception as e:
        logger.error(f"Error creating GitHub issue: {e}")
        return f"Error creating issue: {str(e)}"


# ────────────────────────────────
# 4. Main Analyzer Class
# ────────────────────────────────
class GitRepoAnalyzer:
    """
    Class for analyzing a Git repository, identifying code issues
    and creating GitHub issues for each problem found.
    """

    def __init__(self, repo_path: str, target_folder: str):
        """
        Initializes the repository analyzer.

        Args:
            repo_path: Path to local repository
            target_folder: Folder within the repository to analyze
        """
        self.repo_path = repo_path
        self.target_folder = target_folder

        # Validate that the repo is a valid Git repository
        try:
            self.repo = Repo(repo_path)
        except Exception as e:
            raise ValueError(f"Could not initialize Git repository: {e}")

        # Initialize LangChain agent
        self.agent = initialize_agent(
            tools=[code_analyzer, github_issue_creator, github_pr_creator],
            llm=ChatOpenAI(model=MODEL_NAME, api_key=OPENAI_API_KEY),
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=False,
            handle_parsing_errors=True,
        )

        logger.info(f"Analyzer initialized for {target_folder} in {repo_path}")

    def _detect_eol(self, file_path: str) -> str:
        with open(file_path, 'rb') as f:
            sample = f.read(8192)
        if b'\r\n' in sample:
            return '\r\n'
        return '\n'
    
    # Utility methods for GitHub links
    def _commit_sha(self) -> str:
        """Gets the SHA of the current commit on the current branch"""
        return self.repo.head.commit.hexsha

    def _file_url(self, file_path: str) -> str:
        """
        Generates GitHub URL for a file in the current commit

        Args:
            file_path: Absolute path to the file

        Returns:
            GitHub URL for the file
        """
        rel_path = os.path.relpath(file_path, self.repo_path)
        return f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/blob/{self._commit_sha()}/{rel_path}"

    def _line_url(self, file_path: str, line_number: int) -> str:
        """
        Generates GitHub URL for a specific line in a file

        Args:
            file_path: Absolute path to the file
            line_number: Line number

        Returns:
            GitHub URL with anchor to the specific line
        """
        return f"{self._file_url(file_path)}#L{line_number}"

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyzes an individual Python file and creates issues for problems found

        Args:
            file_path: Absolute path to the Python file

        Returns:
            List of dictionaries with information about created issues
        """
        logger.info(f"Analyzing file: {os.path.basename(file_path)}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return []

        # Prepare input for the analyzer
        input_str = f"{file_path}\n<<<CODE>>>\n{code}"

        try:
            # Invoke agent to execute code_analyzer
            response = self.agent.invoke(
                {"input": f"Analyze this file:\n{input_str}"}
            )
            if isinstance(response, dict):
                res_json = response.get("output", "")
            else:
                res_json = response
            try:
                issues_dict = json.loads(res_json)
            except json.JSONDecodeError:
                logger.error(f"Response is not valid JSON: {res_json[:80]}...")
                return []
            issues = issues_dict.get("issues", [])

            if not issues:
                logger.info(
                    f"No problems found in {os.path.basename(file_path)}"
                )
                return []

            logger.info(
                f"Found {len(issues)} problems in {os.path.basename(file_path)}"
            )
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            return []

        created_issues = []
        for issue in issues:
            try:
                # Build issue body with improved formatting
                file_name = os.path.basename(file_path)
                line_url = self._line_url(file_path, issue["line_number"])

                body = f"""
## Problem detected by AI

**File:** [{file_name}]({line_url})  
**Line:** {issue['line_number']}  
**Type:** {issue['type']}  
**Severity:** {issue['severity']}

### Description
{issue['description']}

### Original code
```python
{issue['original_code']}
```

### Proposed solution
```python
{issue['solution']}
```

### Conceptual diff
```diff
{issue['diff']}
```

---
*This issue was automatically generated by an AI code analysis*
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
                logger.info(f"Issue created: {issue_url}")

                # ---------- 2) if NOT HIGH, move to the next one ------------
                if issue["severity"].upper() != "HIGH":
                    created_issues.append({"url": issue_url, **issue})
                    continue

                # ---------- 3) create branch, commit and push ----------------------
                branch = self._create_branch_name(issue["title"])
                try:
                    self._apply_patch(
                        file_path, issue["line_number"],  issue["original_code"], issue["solution"]
                    )
                    self._commit_and_push(
                        branch,
                        [os.path.relpath(file_path, self.repo_path)],
                        f"fix: {issue['title']} (auto-generated by AI)",
                    )
                except Exception as e:
                    logger.error(f"Could not push the branch: {e}")
                    issue_obj.create_comment(
                        f"❌ Error creating automatic branch/commit: {e}"
                    )
                    continue

                # ---------- 4) create Pull-Request -----------------------------
                pr_title = f"AI FIX: {issue['title']}"
                pr_body = (
                    f"Closes #{issue_number}\n\n"
                    "Applied the solution suggested by AI."
                )
                pr_url = github_pr_creator.invoke(
                    title=pr_title,
                    body=pr_body,
                    head_branch=branch,
                    base_branch="main",
                )
                logger.info(f"PR created: {pr_url}")

                # ---------- 5) comment on the issue with links --------------
                issue_obj.create_comment(
                    f"🚀 A Pull-Request has been opened **[{pr_title}]({pr_url})**\n"
                    f"Branch: `{branch}`"
                )

                created_issues.append(
                    {"url": issue_url, "pr_url": pr_url, "branch": branch, **issue}
                )

            except Exception as e:
                logger.error(f"Error creating issue: {e}")

        return created_issues

    def analyze_folder(self):
        """
        Analyzes all Python files in the target folder and creates issues for problems.
        """
        folder_abs = os.path.join(self.repo_path, self.target_folder)
        py_files = glob.glob(f"{folder_abs}/**/*.py", recursive=True)

        if not py_files:
            logger.warning(f"No Python files found in {self.target_folder}")
            print(f"⚠️ No Python files found in {self.target_folder}")
            return

        logger.info(
            f"Analyzing {len(py_files)} Python files in {self.target_folder}"
        )
        print(f"🔍 Found {len(py_files)} Python files to analyze")

        # Analyze each file and log results
        file_summaries = {}
        total_issues = 0

        for path in py_files:
            file_name = os.path.basename(path)
            print(f"🔍 Analyzing {file_name}...")

            issues = self.analyze_file(path)
            if issues:
                rel_path = os.path.relpath(path, self.repo_path)
                file_summaries[rel_path] = {
                    "issues": issues,
                    "issues_count": len(issues),
                }
                total_issues += len(issues)
                print(f"⚠️ Found {len(issues)} problems in {file_name}")
            else:
                print(f"✅ No problems found in {file_name}")

        # Create summary issue if problems were found
        if file_summaries:
            logger.info(
                f"Creating summary for {len(file_summaries)} files with problems"
            )
            print(
                f"\n📊 Creating summary for {len(file_summaries)} files with {total_issues} problems in total"
            )
            self.create_summary_issue(file_summaries)
        else:
            logger.info("No problems found in any file")
            print("\n✅ No problems found in any analyzed file!")

    def create_summary_issue(self, file_summaries: Dict[str, Dict[str, Any]]):
        """
        Creates a summary issue that compiles all found problems

        Args:
            file_summaries: Dictionary with issue information by file
        """
        print(f"🔍 Creating summary issue...")
        logger.info(f"Attempting to create summary issue for {self.target_folder}")
        # Note: 'body' variable is not defined at this point in the original code
        # logger.debug(f"Size of the summary issue body: {len(body)} characters")

        total_issues = sum(d["issues_count"] for d in file_summaries.values())

        # Build issue body with improved formatting
        body = f"""# 📑 AI Analysis Report: `{self.target_folder}`

## Executive Summary
- **Analysis date:** {os.popen('date').read().strip()}
- **Analyzed commit:** [`{self._commit_sha()[:7]}`](https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commit/{self._commit_sha()})
- **Files with issues:** **{len(file_summaries)}**
- **Total detected issues:** **{total_issues}**

## 📋 Details by file
"""
        # Counters for statistics
        issues_by_type = {}
        issues_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Add details by file
        for file_rel, data in sorted(file_summaries.items()):
            file_url = self._file_url(os.path.join(self.repo_path, file_rel))
            body += f"\n### [{file_rel}]({file_url})\n"
            print(f"🔍 Analyzing {file_rel}...")

            # Group issues by type in this file
            file_issues_by_type = {}
            for issue in data["issues"]:
                issue_type = issue["type"]
                if issue_type not in file_issues_by_type:
                    file_issues_by_type[issue_type] = []
                file_issues_by_type[issue_type].append(issue)

                # Update global counters
                issues_by_type[issue_type] = issues_by_type.get(issue_type, 0) + 1
                issues_by_severity[issue["severity"]] += 1

            # Show issues grouped by type
            for issue_type, issues_list in file_issues_by_type.items():
                body += f"**{issue_type}:**\n"
                for issue in issues_list:
                    body += (
                        f"- [{issue['title']}]({issue['url']}) ({issue['severity']})\n"
                    )

            body += "\n"

        # Add statistics
        body += "\n## 📊 Statistics\n"

        # By type
        body += "\n### By issue type\n"
        for issue_type, count in sorted(
            issues_by_type.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_issues) * 100
            body += f"- **{issue_type}:** {count} ({percentage:.1f}%)\n"

        # By severity
        body += "\n### By severity level\n"
        for severity, count in sorted(
            issues_by_severity.items(),
            key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x[0]],
        ):
            if count > 0:
                percentage = (count / total_issues) * 100
                body += f"- **{severity}:** {count} ({percentage:.1f}%)\n"

        # Final recommendations
        body += """
## 🔍 Recommended next steps

1. Review each issue individually, starting with HIGH severity ones
2. Apply the suggested fixes or implement alternative solutions
3. Run tests to verify that solutions don't introduce new problems
4. Consider adding automated tests to prevent regressions

---
*This report was automatically generated through AI code analysis*
"""

        # Create the summary issue
        payload = {
            "title": f"📊 AI Global Report: {self.target_folder}",
            "body": body,
            "labels": ["summary", "ai-analysis", "technical-debt"],
        }

        print(f"🔍 Creating summary issue...")
        print(f"📌 Summary issue payload: {json.dumps(payload, indent=2)}")
        try:
            url = self.agent.invoke(
                {
                    "input": f"Create a summary issue with this payload:\n```json\n{json.dumps(payload)}\n```"
                }
            ).get("output", "")

            if url and not url.startswith("Error"):
                logger.info(f"Summary issue created: {url}")
                print(f"📌 Summary issue created: {url}")
            else:
                logger.error(f"Error creating summary issue: {url}")
                print("❌ Could not create summary issue")
        except Exception as e:
            logger.error(f"Error creating summary issue: {e}")
            print(f"❌ Error creating summary issue: {e}")

    def _create_branch_name(self, issue_title: str) -> str:
        date = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        slug = slugify(issue_title)[:25]
        return f"ai/fix/{slug}-{date}"

    def _apply_patch(self, file_path: str, line_num: int, original_code: str, new_code: str):
        # 1) read preserving exact line ending
        eol = self._detect_eol(file_path)
        
        try:
            # Using encoding='utf-8' explicitly is good practice
            with open(file_path, "r", newline='') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {file_path} to apply patch: {e}")
            raise  # Re-throw the exception so the process fails cleanly

        # Make sure line number is valid
        if line_num <= 0 or line_num > len(lines):
             logger.error(f"Invalid line number ({line_num}) for file {file_path} with {len(lines)} lines.")
             # Decide how to handle this error: continue, raise exception?
             # For now, we raise an exception to stop the process for this issue.
             raise ValueError(f"Invalid line number: {line_num}")

        idx = line_num - 1 # 0-based index
        
        # Get original indentation
        original_indent = re.match(r"\s*", lines[idx]).group(0) if idx < len(lines) else "" # Ensure idx is valid

        # --- START CHANGE ---
        # Calculate how many lines the detected original code occupies
        # Use splitlines() to correctly handle different EOLs when counting
        # Add a fallback to 1 if original_code is empty or None for some reason
        num_original_lines = len(original_code.splitlines()) if original_code else 1
        # Make sure not to try to replace beyond the end of file
        num_original_lines = min(num_original_lines, len(lines) - idx)
        if num_original_lines <= 0:
             num_original_lines = 1 # At minimum, replace the line indicated by line_num

        logger.info(f"Applying patch in {os.path.basename(file_path)}:{line_num}. Replacing {num_original_lines} line(s).")
        # --- END CHANGE ---


        # 2) maintain original indentation (of the FIRST line to replace)
        original_indent = re.match(r"\s*", lines[idx]).group(0)
        if not _is_valid_python(new_code):
            logger.warning("The replacement provided by AI does not appear to be valid Python code.")
            # Consider what to do here. Mark the issue? Don't apply?
            # For now, you could add a TODO as you had, or raise an error.
            #new_code = f"# TODO: Review invalid AI code:\n# {new_code.replace('\n', '\n# ')}"
            #new_code = + "\n"+original_code
            # Or better, don't apply the patch if it's not valid:
            #raise ValueError("The solution proposed by AI is not valid Python code.")
            return False


        # Prepare new lines with correct indentation and original EOL
        # Dedent cleans up the base indentation of the AI solution.
        new_lines_content = textwrap.dedent(new_code).splitlines() # splitlines() removes EOLs

        prepared_new_lines = []
        if new_lines_content: # If there's new content
            for line in new_lines_content:
                # Apply original indentation. Don't use rstrip() here to preserve intentional trailing spaces.
                prepared_line = original_indent + line
                prepared_new_lines.append(prepared_line + eol) # Add the detected EOL
        # If new_lines_content is empty, prepared_new_lines will be [], removing the original lines.

        # 3) replace the correct REGION
        # Make sure the slice doesn't exceed the bounds
        end_idx = min(idx + num_original_lines, len(lines))
        lines[idx : end_idx] = prepared_new_lines

        # 4) write with EOL preserved by newline='' and UTF-8
        try:
            # Use explicit encoding='utf-8' when writing too
            with open(file_path, "w", encoding='utf-8', newline='') as f:
                f.writelines(lines)
            logger.info(f"Patch successfully applied to {os.path.basename(file_path)}:{line_num}.")
        except Exception as e:
            logger.error(f"Error writing patch to {file_path}: {e}")
            raise # Re-throw to stop the process

    def _commit_and_push(self, branch: str, files_to_add: List[str], message: str):
        origin = self.repo.remote(name="origin")
        # Create local branch (if it doesn't exist)
        if branch not in self.repo.heads:
            self.repo.git.checkout("-b", branch)
        else:
            self.repo.git.checkout(branch)

        # Add and commit
        self.repo.index.add(files_to_add)
        self.repo.index.commit(message)

        # Push (origin needs to use https://x-access-token:TOKEN@... or already authorized ssh-agent)
        origin.push(branch)


def main():
    """Main function that runs the analysis"""
    print("\n🔍 GitHub Issue Creator - Code Analysis 🔍\n")

    try:
        repo_path = input("Path to local repository: ").rstrip("/")
        target_folder = input("Folder to analyze (relative to repo): ").rstrip("/")

        # Validate paths
        if not os.path.isdir(repo_path):
            print(f"❌ Path {repo_path} doesn't exist or is not a directory")
            return

        folder_path = os.path.join(repo_path, target_folder)
        if not os.path.isdir(folder_path):
            print(f"❌ Folder {target_folder} doesn't exist in the repository")
            return

        # Confirm operation
        print(f"\n📁 Will analyze: {folder_path}")
        confirm = input("Continue? (y/n): ").lower()
        if confirm != "y":
            print("❌ Operation cancelled")
            return

        # Run analysis
        print("\n🚀 Starting analysis...\n")
        analyzer = GitRepoAnalyzer(repo_path, target_folder)
        analyzer.analyze_folder()

        print("\n✅ Analysis completed!\n")

    except KeyboardInterrupt:
        print("\n❌ Operation interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Error in main execution")


if __name__ == "__main__":
    main()