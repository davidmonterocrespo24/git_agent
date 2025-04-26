import os
import re
import glob
import json
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import ast, tempfile
import chardet
import traceback
from git import Repo, GitCommandError  # Import GitCommandError
from github import Github
import textwrap
from slugify import slugify  # pip install python-slugify
import datetime as _dt
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from langchain.agents import AgentType, initialize_agent, tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage
from diff_match_patch import diff_match_patch

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
You are an expert Python code analyst AI with deep knowledge of optimization techniques, security vulnerabilities, common error patterns, and Python best practices (including PEP 8).

TASK:
Analyze the provided Python code block below the marker `--- CODE START ---` and identify issues across the following categories:

1.  **ERROR**: Logical flaws, potential runtime exceptions (e.g., `IndexError`, `TypeError`), off-by-one errors, incorrect assumptions, or behaviors that deviate from probable intent.
2.  **PERFORMANCE**: Inefficiencies, performance bottlenecks, suboptimal algorithm choices, unnecessary computations, inefficient use of data structures, or blocking I/O operations.
3.  **IMPROVEMENT**: Opportunities to enhance readability, maintainability, or adherence to Pythonic idioms and PEP 8 standards. This includes overly complex logic, non-descriptive naming, lack of comments where needed, or violations of the DRY (Don't Repeat Yourself) principle.
4.  **SECURITY**: Potential security vulnerabilities, unsafe practices, or exposure to common threats. Examples include SQL injection, cross-site scripting (XSS) vectors, hardcoded secrets, insecure handling of external input, use of deprecated/unsafe modules or functions (like `pickle` with untrusted data).

IMPORTANT INSTRUCTIONS:
* Return **EXCLUSIVELY** a single, valid JSON object adhering precisely to the schema below.
* Do **NOT** include any explanatory text, greetings, apologies, or any other content outside the JSON structure.
* If no significant issues are found, respond **ONLY** with: `{ "issues": [] }`
* Analyze the code **as provided**. Do not make assumptions about external context or missing imports unless explicitly stated in the code.
* Focus on concrete issues within the provided code snippet.

JSON SCHEMA:
{
  "issues": [
    {
     "type": "ERROR | PERFORMANCE | IMPROVEMENT | SECURITY", // Must be one of these exact strings
      "title": "Concise, descriptive title of the issue (max 15 words)",
      "line_number": integer, // The primary line number where the issue occurs or starts
      "description": "Detailed explanation: Clearly describe the issue, why it's problematic, and its potential impact.",
      "original_code": "The specific line(s) of original code relevant to the issue. Preserve indentation.",
      "solution": "The corrected or improved code fragment intended to replace 'original_code'. Provide ONLY the code, preserving indentation. Should be runnable in context.",
      "diff": "Code (conceptual diff)",
      "severity": "HIGH|MEDIUM|LOW" 
    }
  ]
}

SEVERITY GUIDELINES:
* **HIGH**: Critical issues likely to cause program failure, incorrect results, data loss/corruption, or significant security vulnerabilities.
* **MEDIUM**: Important issues impacting performance noticeably, hindering maintainability significantly, or representing moderate security risks.
* **LOW**: Minor issues related to style, readability, best practices, or potential micro-optimizations with limited impact.

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

    def __init__(self, repo_path: str, target_folder: str, base_branch: str = None):
        """
        Initializes the repository analyzer.

        Args:
            repo_path: Path to local repository
            target_folder: Folder within the repository to analyze
        """
        self.repo_path = repo_path
        self.target_folder = target_folder
        self.dmp = diff_match_patch()

        # Validate that the repo is a valid Git repository
        try:
            self.repo = Repo(repo_path)
            self.base_branch = base_branch or self.repo.active_branch.name
        except Exception as e:
            raise ValueError(f"Could not initialize Git repository: {e}")

        # Initialize LangChain agent
        self.agent = initialize_agent(
            tools=[code_analyzer, github_pr_creator],
            llm=ChatOpenAI(model=MODEL_NAME, api_key=OPENAI_API_KEY),
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=False,
            handle_parsing_errors=True,
        )

        logger.info(f"Analyzer initialized for {target_folder} in {repo_path}")

    def _detect_eol_and_encoding(self, file_path: str) -> tuple[str, str]:
        """Detects line ending ('\n' or '\r\n') and file encoding."""
        try:
            with open(file_path, "rb") as f:
                # Read a larger sample for encoding detection, or whole file if small
                sample = f.read(16384)  # Read more for better encoding detection
                f.seek(0)  # Go back to start
                full_content_bytes = f.read()

            detection = chardet.detect(full_content_bytes)
            encoding = detection["encoding"] if detection["encoding"] else "utf-8"
            # Normalize common variations
            if encoding.lower() in ["ascii"]:
                encoding = "utf-8"  # Treat ASCII as UTF-8 subset

            # Detect EOL from the sample
            eol = "\n"  # Default to LF
            if b"\r\n" in sample:
                eol = "\r\n"
            elif b"\r" in sample and b"\n" not in sample:
                eol = "\r"  # Handle classic Mac OS EOL if necessary

            logger.debug(
                f"Detected EOL='{eol.encode()}' Encoding='{encoding}' for {os.path.basename(file_path)}"
            )
            return eol, encoding
        except Exception as e:
            logger.error(f"Error detecting EOL/Encoding for {file_path}: {e}")
            return "\n", "utf-8"  # Fallback defaults

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
        file_name = os.path.basename(file_path)
        logger.info(f"Starting analysis for: {file_name}")

        try:
            _eol, encoding = self._detect_eol_and_encoding(file_path)
            # Read with universal newline support, let Python handle EOL internally for now
            with open(file_path, "r", encoding=encoding, newline="") as f:
                code = f.read()
            if not code:
                logger.warning(f"File {file_name} is empty, skipping analysis.")
                return []
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            traceback.print_exc()
            return []

        try:
            analyzer_response_str = code_analyzer.invoke(
                {"file_path": file_path, "code": code}
            )
            issues_dict = json.loads(analyzer_response_str)
        except json.JSONDecodeError as json_err:
            logger.error(
                f"Failed to decode JSON response from code_analyzer for {file_name}: {json_err}"
            )
            logger.error(
                f"Response was: {analyzer_response_str[:500]}..."
            )  # Log problematic response
            return []
        except Exception as tool_err:
            logger.error(
                f"Error invoking code_analyzer tool for {file_name}: {tool_err}"
            )
            traceback.print_exc()
            return []

        if "error" in issues_dict:
            logger.error(f"Analysis for {file_name} failed: {issues_dict['error']}")
            return []

        issues = issues_dict.get("issues", [])
        if not issues:
            logger.info(f"No significant issues found in {file_name}")
            return []

        logger.info(f"Found {len(issues)} potential issues in {file_name}")
        created_issues_summary = []

        # --- Ensure we are on the base branch before processing issues ---
        try:
            if self.repo.is_dirty(untracked_files=True):
                logger.warning(
                    f"Repo is dirty before processing {file_name}. Stashing changes."
                )
                self.repo.git.stash("save", f"ai-analyzer-stash-{file_name}")

            base_branch_name = self.base_branch
            if self.repo.active_branch.name != base_branch_name:
                logger.info(f"Switching back to base branch '{base_branch_name}'")
                self.repo.git.checkout(base_branch_name)
                # Optional: Pull latest changes from base branch
                # try:
                #     origin = self.repo.remote(name='origin')
                #     origin.pull()
                #     logger.info(f"Pulled latest changes from origin/{base_branch_name}")
                # except Exception as pull_err:
                #     logger.warning(f"Could not pull latest changes from origin/{base_branch_name}: {pull_err}")

        except Exception as e:
            logger.error(
                f"Error preparing git state before processing {file_name}: {e}. Skipping auto-fixes for this file."
            )
            # We can still create issues, but disable patching for this file run
            can_patch = False
        else:
            can_patch = True  # Git state is clean and on base branch

        # --- Process issues: Create Issue first, then optionally Patch & PR ---
        for issue in issues:
            issue_info_for_summary = {
                "type": issue["type"],
                "title": issue["title"],
                "severity": issue["severity"],
                "url": issue_url
            }
            try:
                # --- 1) Create GitHub Issue ---
                file_rel_path = os.path.relpath(file_path, self.repo_path).replace(
                    "\\", "/"
                )
                line_url = self._line_url(
                    file_path, issue.get("line_number", 1)
                )  # Use get with default

                # Validate required issue fields from LLM response
                required_fields = [
                    "type",
                    "title",
                    "line_number",
                    "description",
                    "original_code",
                    "solution",
                    "severity",
                ]
                if not all(field in issue for field in required_fields):
                    logger.warning(
                        f"Skipping issue due to missing fields in LLM response: {issue}"
                    )
                    continue

                # Ensure line number is valid before using it
                try:
                    line_num_int = int(issue["line_number"])
                    if line_num_int <= 0:
                        raise ValueError("Line number must be positive")
                except (ValueError, TypeError) as L_err:
                    logger.warning(
                        f"Invalid line number '{issue.get('line_number')}' for issue '{issue.get('title')}'. Skipping. Error: {L_err}"
                    )
                    continue

                # Build issue body
                issue_body = f"""## Problem detected by AI

**File:** [{file_rel_path}]({self._file_url(file_path)})
**Line:** [{issue['line_number']}]({line_url})
**Type:** `{issue['type']}`
**Severity:** `{issue['severity']}`

### Description
{issue.get('description', 'N/A')}

### Original Code Snippet
```python
{issue.get('original_code', 'N/A')}
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

                created_gh_issue = repo.create_issue(
                    title=f"[{issue['type']}][{issue['severity']}] {issue['title']}",
                    body=issue_body,
                    labels=[
                        issue["type"].lower(),
                        f"severity:{issue['severity'].lower()}",
                        "ai-detected",
                    ],
                )
                issue_number = created_gh_issue.number
                issue_url = created_gh_issue.html_url
                logger.info(f"Issue created: {issue_url}")
                issue_info_for_summary = {"url": issue_url, **issue} # Basic info for summary

                # ---------- 2) if NOT HIGH, move to the next one ------------
                # Only patch if git state was clean and severity is HIGH/MEDIUM
                should_attempt_patch = can_patch and issue["severity"].upper() in [
                    "HIGH",
                    "MEDIUM",
                ]

                if not should_attempt_patch:
                    if not can_patch:
                        logger.warning(
                            f"Skipping auto-patch for issue #{issue_number} due to unclean git state or not being on base branch."
                        )
                    else:
                        logger.info(
                            f"Skipping auto-patch for issue #{issue_number} (Severity: {issue['severity']})"
                        )
                    created_issues_summary.append(issue_info_for_summary)
                    continue  # Move to next issue in the file

                # ---------- 3) create branch, commit and push ----------------------
                logger.info(f"Attempting auto-patch for issue #{issue_number} (Severity: {issue['severity']})")            
                branch_name = self._create_branch_name(issue["title"], issue_number)
                patch_applied = False
                self.repo.git.checkout(
                    base_branch_name
                )  # Ensure starting from clean base
                self.repo.git.checkout("-b", branch_name)
                logger.info(f"Created and checked out branch: {branch_name}")
                try:
                    self._apply_patch(
                        file_path,
                        issue["line_number"],
                        issue["original_code"],
                        issue["solution"],
                    )
                    patch_applied = True
                    commit_message = f"fix: Apply AI suggestion for issue #{issue_number}\n\n{issue['title']}"
                    self.repo.index.add([file_path])  # Add the specific modified file
                    # Check if there are staged changes before committing
                    if self.repo.index.diff("HEAD"):
                        self.repo.index.commit(commit_message)
                        logger.info(f"Committed changes to branch {branch_name}")

                        # Push the branch
                        origin = self.repo.remote(name="origin")
                        # Ensure correct auth method is configured (SSH key or Token in URL)
                        origin.push(refspec=f"{branch_name}:{branch_name}")
                        logger.info(f"Pushed branch {branch_name} to origin")
                    else:
                        logger.warning(
                            f"Patch application for issue #{issue_number} resulted in no changes to commit."
                        )
                        # No need to create PR if no changes pushed
                        patch_applied = False  # Reset flag
                except GitCommandError as git_err:
                    logger.error(
                        f"Git command error during patch/commit/push for issue #{issue_number} on branch {branch_name}: {git_err}"
                    )
                    created_gh_issue.create_comment(
                        f"⚠️ **AI Auto-Patch Failed:** Git command error occurred.\n```\n{git_err}\n```\nPlease review the suggestion manually."
                    )
                    # Switch back to base branch and clean up failed branch locally
                    self._cleanup_failed_branch(branch_name, base_branch_name)
                except Exception as e:
                    logger.error(f"Could not push the branch: {e}")
                    created_gh_issue.create_comment(
                        f"❌ Error creating automatic branch/commit: {e}"
                    )
                    self._cleanup_failed_branch(branch_name, base_branch_name)
                    continue

                # ---------- 4) create Pull-Request -----------------------------
                if patch_applied:                    
                    pr_title = f"AI Fix #{issue_number}: {issue['title']}"
                    pr_body = f"Closes #{issue_number}\n\nAutomatically applied AI code suggestion.\n\nPlease review carefully."
                    try:
                        # Use the PR creator tool directly
                        pr_url = github_pr_creator.invoke(
                            {
                                "title": pr_title[:255],
                                "body": pr_body,
                                "head_branch": branch_name,
                                "base_branch": base_branch_name,
                            }
                        )

                        if "Error" in pr_url:
                            raise Exception(
                                f"PR creation tool returned error: {pr_url}"
                            )

                        logger.info(
                            f"Successfully created PR for issue #{issue_number}: {pr_url}"
                        )
                        created_gh_issue.create_comment(
                            f"✅ **AI Auto-Patch Successful:** Pull request created: [{pr_title}]({pr_url})"
                        )
                        # Add PR info to the summary for this issue
                        issue_info_for_summary.update(
                            {"pr_url": pr_url, "branch": branch_name}
                        )

                    except Exception as pr_err:
                        logger.error(
                            f"Failed to create PR for branch {branch_name} (Issue #{issue_number}): {pr_err}"
                        )
                        created_gh_issue.create_comment(
                            f"⚠️ **AI Auto-Patch Warning:** Patch was applied and pushed to branch `{branch_name}`, but **failed to create Pull Request**.\nError: ```\n{pr_err}\n```\nPlease create the PR manually."
                        )
                        # Add branch info even if PR failed
                        issue_info_for_summary.update(
                            {"branch": branch_name, "pr_creation_failed": True}
                        )

                # Append summary info (issue URL, potentially PR URL/branch)
                created_issues_summary.append(issue_info_for_summary)

                # --- 5) Return to base branch AFTER processing this issue/PR cycle ---
                logger.debug(
                    f"Returning to base branch '{base_branch_name}' after processing issue #{issue_number}"
                )
                self.repo.git.checkout(base_branch_name)
            except Exception as outer_err:
                logger.error(
                    f"Unhandled error processing an issue in {file_name}: {outer_err}"
                )
                traceback.print_exc()
                # Ensure we try to switch back to base branch if something unexpected happened
                try:
                    if self.repo.active_branch.name != base_branch_name:
                        self.repo.git.checkout(base_branch_name)
                except:  # Catch all exceptions during cleanup checkout
                    logger.error(
                        "Failed to switch back to base branch during error handling."
                    )
                # Add minimal info if possible
                if "issue_info_for_summary" in locals() and issue_info_for_summary:
                    created_issues_summary.append(
                        issue_info_for_summary
                    )  # Add at least the issue URL if created

        try:
            stashes = self.repo.git.stash("list")
            if f"ai-analyzer-stash-{file_name}" in stashes:
                logger.info(f"Popping stashed changes for {file_name}")
                self.repo.git.stash("pop")
        except Exception as stash_err:
            logger.warning(f"Could not pop stash for {file_name}: {stash_err}")

        return created_issues_summary

    def _cleanup_failed_branch(self, branch_name: str, base_branch_name: str):
        """Switches back to base and deletes the failed local branch."""
        logger.warning(f"Cleaning up failed local branch: {branch_name}")
        try:
            self.repo.git.checkout(base_branch_name)
            self.repo.delete_head(branch_name, force=True)
            logger.info(f"Deleted local branch {branch_name}")
        except Exception as e:
            logger.error(
                f"Error cleaning up branch {branch_name}: {e}. Manual cleanup might be required."
            )

    def analyze_folder(self):
        """Analyzes all Python files in the target folder."""
        folder_abs = os.path.join(self.repo_path, self.target_folder)
        # Use glob with recursive=True and include_hidden=False (or True if needed)
        # Ensure path separators are correct for the OS
        glob_pattern = os.path.join(folder_abs, "**", "*.py")
        py_files = glob.glob(glob_pattern, recursive=True)

        if not py_files:
            logger.warning(
                f"No Python files found in {folder_abs} using pattern {glob_pattern}"
            )
            print(f"⚠️ No Python files found in {self.target_folder}")
            return

        logger.info(f"Found {len(py_files)} Python files in {self.target_folder}")
        print(
            f"🔍 Found {len(py_files)} Python files to analyze in {self.target_folder}"
        )

        file_summaries = {}
        total_issues_found = 0  # Count issues reported by LLM initially
        total_issues_created = 0  # Count issues successfully created on GitHub

        original_branch = self.repo.active_branch.name
        logger.info(f"Starting analysis from branch: {original_branch}")

        for file_path in py_files:
            # Make path relative for display
            file_rel_path = os.path.relpath(file_path, self.repo_path).replace(
                "\\", "/"
            )
            print(f"\n🔍 Analyzing {file_rel_path}...")
            try:
                # Reset git state to base branch before analyzing each file
                # self.repo.git.checkout("main") # Consider if this is needed before each file or just once before the loop

                issue_details_list = self.analyze_file(file_path)

                if issue_details_list:
                    num_issues_in_file = len(issue_details_list)
                    total_issues_created += num_issues_in_file
                    # Store the detailed list which includes URLs etc.
                    file_summaries[file_rel_path] = {
                        "issues": issue_details_list,
                        "issues_count": num_issues_in_file,
                    }
                    print(
                        f"✅ Finished analyzing {file_rel_path}. Created {num_issues_in_file} GitHub issue(s)."
                    )
                    # Note: total_issues_found might differ if some LLM issues failed validation/creation
                else:
                    print(
                        f"✅ Finished analyzing {file_rel_path}. No GitHub issues created."
                    )

            except Exception as file_analysis_err:
                logger.error(
                    f"Critical error during analysis of {file_rel_path}: {file_analysis_err}"
                )
                print(f"❌ Error analyzing {file_rel_path}. See logs for details.")
                traceback.print_exc()
                # Ensure we are back on the original branch if something went wrong
                try:
                    if self.repo.active_branch.name != original_branch:
                        self.repo.git.checkout(original_branch)
                except Exception as checkout_err:
                    logger.error(
                        f"Failed to return to original branch '{original_branch}' during error handling: {checkout_err}"
                    )

            finally:
                # Optional: Add delay between files if hitting rate limits
                # import time
                # time.sleep(1)
                pass

        # --- Create Summary Issue ---
        if file_summaries:
            logger.info(
                f"Analysis complete. Creating summary issue for {len(file_summaries)} files with {total_issues_created} issues."
            )
            print(
                f"\n📊 Creating summary issue for {len(file_summaries)} files ({total_issues_created} issues created)..."
            )
            # Use the direct PyGithub method
            self.create_summary_issue_direct(file_summaries)
        else:
            logger.info("Analysis complete. No issues were created.")
            print("\n✅ Analysis finished. No actionable issues were found or created.")

        # --- Final Step: Return to the original branch ---
        try:
            if self.repo.active_branch.name != original_branch:
                logger.info(f"Returning to original branch: {original_branch}")
                self.repo.git.checkout(original_branch)
        except Exception as e:
            logger.error(
                f"Could not return to original branch '{original_branch}': {e}"
            )

    def create_summary_issue_direct(self, file_summaries: Dict[str, Dict[str, Any]]):
        """Creates the summary issue directly using PyGithub."""
        total_issues = sum(d["issues_count"] for d in file_summaries.values())
        now_utc = datetime.now(timezone.utc)

        # Build issue body
        body = f"# 📑 AI Code Analysis Report: `{self.target_folder}`\n\n"
        body += (
            f"Analysis completed on **{now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}**\n"
        )
        body += f"Analyzed commit: [`{self._commit_sha()[:7]}`]({self._file_url(self.repo_path).replace('/blob/', '/commit/')})\n"  # Link to commit
        body += f"- **Files with issues:** {len(file_summaries)}\n"
        body += f"- **Total GitHub issues created:** {total_issues}\n\n"
        body += "## 📋 Issues Summary by File\n"

        issues_by_type = {}
        issues_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        auto_patched_count = 0

        for file_rel, data in sorted(file_summaries.items()):
            file_abs_path = os.path.join(self.repo_path, file_rel)
            file_url = self._file_url(file_abs_path)
            body += f"\n### [{file_rel}]({file_url}) ({data['issues_count']} issues)\n"

            for issue in data["issues"]:
                # Use .get() for safety, though validation should ensure keys exist
                issue_type = issue.get("type", "UNKNOWN")
                severity = issue.get("severity", "UNKNOWN").upper()
                title = issue.get("title", "Untitled Issue")
                issue_url = issue.get("url", "#")  # Link to the created GitHub issue

                body += f"- [{severity}] [{title}]({issue_url})"
                if issue.get("pr_url"):
                    body += f" ([PR]({issue['pr_url']}))"
                    auto_patched_count += 1
                elif issue.get("branch") and issue.get("pr_creation_failed"):
                    body += f" (Fix branch: `{issue['branch']}` - PR Failed)"
                elif issue.get(
                    "branch"
                ):  # Patch applied but no PR attempt (e.g., wrong severity)
                    body += f" (Fix branch: `{issue['branch']}`)"
                body += "\n"

                # Update stats
                issues_by_type[issue_type] = issues_by_type.get(issue_type, 0) + 1
                if severity in issues_by_severity:
                    issues_by_severity[severity] += 1

        # Add statistics
        body += "\n## 📊 Statistics\n"

        if total_issues > 0:
            body += "\n### By Issue Type\n"
            for issue_type, count in sorted(
                issues_by_type.items(), key=lambda item: item[1], reverse=True
            ):
                percentage = (count / total_issues) * 100
                body += f"- **{issue_type}:** {count} ({percentage:.1f}%)\n"

            body += "\n### By Severity Level\n"
            severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            for severity, count in sorted(
                issues_by_severity.items(),
                key=lambda item: severity_order.get(item[0], 99),
            ):
                if count > 0:
                    percentage = (count / total_issues) * 100
                    body += f"- **{severity}:** {count} ({percentage:.1f}%)\n"

            if auto_patched_count > 0:
                patch_percentage = (auto_patched_count / total_issues) * 100
                body += f"\n### Auto-Patching\n"
                body += f"- Issues automatically patched & PR created: {auto_patched_count} ({patch_percentage:.1f}%)\n"

        else:
            body += "No issues created.\n"

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
            "title": f"📊 AI Analysis Summary: {self.target_folder} ({now_utc.strftime('%Y-%m-%d')})",
            "body": body,
            "labels": ["summary", "ai-analysis", "technical-debt"],
        }

        print(f"🔍 Creating summary issue...")
        print(f"📌 Summary issue payload: {json.dumps(payload, indent=2)}")
        try:
            gh = Github(GITHUB_TOKEN)
            repo = gh.get_repo(f"{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
            issue = repo.create_issue(
                title=payload["title"], body=payload["body"], labels=payload["labels"]
            )
            url = issue.html_url

            if url and not url.startswith("Error"):
                logger.info(f"Summary issue created: {url}")
                print(f"📌 Summary issue created: {url}")
            else:
                logger.error(f"Error creating summary issue: {url}")
                print("❌ Could not create summary issue")
        except Exception as e:
            logger.error(f"Error creating summary issue: {e}")
            print(f"❌ Error creating summary issue: {e}")

    def _create_branch_name(self, issue_title: str, issue_number: int) -> str:
        """Creates a unique branch name for the fix."""
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y%m%d")
        # Sanitize title for branch name
        slug = slugify(issue_title, max_length=40, word_boundary=True, save_order=True)
        return f"ai/fix/{date_str}/{issue_number}-{slug}"

    def _apply_patch(
        self,
        file_path: str,
        line_num: int,
        original_code_snippet: str,
        new_code_snippet: str,
    ):
        """
        Generates a patch using diff-match-patch and applies it using `git apply`.
        """
        logger.info(
            f"Generating patch for {os.path.basename(file_path)} at line {line_num}"
        )
        file_basename = os.path.basename(file_path)

        eol, encoding = self._detect_eol_and_encoding(file_path)

        try:
            # Read the original file content accurately
            with open(file_path, "r", encoding=encoding, newline="") as f:
                original_lines = (
                    f.readlines()
                )  # Read lines with original EOLs preserved by newline=''
            original_full_content = "".join(original_lines)

        except Exception as e:
            logger.error(f"Error reading file {file_path} for patching: {e}")
            raise  # Re-raise the exception

        # --- Construct the *intended* modified content ---
        # This part still requires careful handling of lines and indentation
        idx = line_num - 1  # 0-based index

        if idx < 0 or idx >= len(original_lines):
            # Log the problematic original_lines list if needed
            # logger.debug(f"Original lines ({len(original_lines)}): {original_lines}")
            raise ValueError(
                f"Invalid line number {line_num} for file {file_path} with {len(original_lines)} lines."
            )

        # Get original indentation from the target line
        original_indent = re.match(r"^\s*", original_lines[idx]).group(0)

        # Determine number of lines in the original snippet *provided by AI*
        # Use splitlines() which handles various EOLs for counting
        num_original_snippet_lines = (
            len(original_code_snippet.splitlines()) if original_code_snippet else 1
        )
        # Ensure we don't go past the end of the file
        num_original_snippet_lines = min(
            num_original_snippet_lines, len(original_lines) - idx
        )
        if num_original_snippet_lines <= 0:
            num_original_snippet_lines = 1  # Should replace at least one line

        # Prepare the new code lines, applying original indent and EOL
        # Dedent the AI's solution first to remove its base indentation
        new_code_dedented = textwrap.dedent(
            new_code_snippet
        ).splitlines()  # Removes EOLs
        prepared_new_lines = []
        if new_code_dedented:
            for line in new_code_dedented:
                # Add original indent, the line content, and detected EOL
                prepared_new_lines.append(original_indent + line + eol)
        # If new_code_dedented is empty, prepared_new_lines remains empty, effectively deleting the original lines.

        # --- Create the modified lines list ---
        modified_lines = (
            original_lines[0:idx] +
            prepared_new_lines +
            original_lines[idx + num_original_snippet_lines:]
        )
        modified_full_content = "".join(modified_lines)
        original_full_content = "".join(original_lines) # For comparison

        # Check if content actually changed
        if original_full_content == modified_full_content:
            logger.warning(f"Proposed solution for {file_basename}:{line_num} resulted in no change to file content. Skipping modification.")
            return # No change needed

        # --- Write the modified content back to the file ---
        try:
             with open(file_path, "w", encoding=encoding, newline='') as f:
                  f.writelines(modified_lines)
             logger.info(f"Successfully wrote modifications to {file_basename}")
        except Exception as e:
            logger.error(f"Error writing modifications back to {file_path}: {e}")
            # Consider restoring original content if write fails? Complex. Better to fail.
            raise # Re-raise the exception

        # --- Stage the changes using git add ---
        try:
            self.repo.index.add([file_path])
            logger.info(f"Successfully staged changes in {file_basename} using git add.")
        except GitCommandError as e:
            logger.error(f"git add failed for {file_basename}!")
            logger.error(f"Command: {e.command}")
            logger.error(f"Status: {e.status}")
            logger.error(f"Stderr: {e.stderr.strip()}")
            # Attempt to reset the file in the working directory if add fails?
            try:
                self.repo.git.checkout('--', file_path)
                logger.warning(f"Attempted to reset {file_basename} in working directory after git add failure.")
            except Exception as reset_err:
                logger.error(f"Could not reset {file_basename} after git add failure: {reset_err}")
            raise # Re-raise the GitCommandError
        except Exception as e:
             logger.error(f"An unexpected error occurred during git add: {e}")
             # Also try reset here
             try:
                 self.repo.git.checkout('--', file_path)
                 logger.warning(f"Attempted to reset {file_basename} in working directory after unexpected git add error.")
             except Exception as reset_err:
                 logger.error(f"Could not reset {file_basename} after unexpected git add error: {reset_err}")
             raise

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
        traceback.print_exc()
        logger.exception("Error in main execution")


if __name__ == "__main__":
    main()
