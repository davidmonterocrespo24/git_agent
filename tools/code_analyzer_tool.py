import json
import os
import re

from config.settings import settings
from langchain.agents import tool
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from models.analyzer_input import AnalyzerInput
from prompt.system_prompt_template import SYSTEM_TEMPLATE

from git_agent.log import logger


@tool(
    "code_analyzer",
    args_schema=AnalyzerInput,
    return_direct=True,
    description="Analyzes Python code and returns JSON with issues",
)
def code_analyzer(Settings, file_path: str, code: str) -> str:
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
        llm = ChatOpenAI(model=settings.MODEL_NAME, api_key=settings.OPENAI_API_KEY)

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
