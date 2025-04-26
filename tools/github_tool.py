import json

from config.settings import settings
from github import Github
from langchain.agents import tool
from models.analyzer_input import AnalyzerInput
from models.pr import PRPayload

from git_agent.log import logger


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
        gh = Github(settings.GITHUB_TOKEN)
        repo = gh.get_repo(f"{settings.GITHUB_REPO_OWNER}/{settings.GITHUB_REPO_NAME}")
        issue = repo.create_issue(title=title, body=body, labels=labels)
        logger.info(f"Issue created: {issue.html_url}")
        return issue.html_url
    except Exception as e:
        logger.error(f"Error creating GitHub issue: {e}")
        return f"Error creating issue: {str(e)}"


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
        gh = Github(settings.GITHUB_TOKEN)
        repo = gh.get_repo(f"{settings.GITHUB_REPO_OWNER}/{settings.GITHUB_REPO_NAME}")
        pr = repo.create_pull(
            title=title, body=body, head=head_branch, base=base_branch, draft=False
        )
        logger.info(f"PR created: {pr.html_url}")
        return pr.html_url
    except Exception as e:
        logger.error(f"Error creating PR: {e}")
        return f"Error creating PR: {e}"
