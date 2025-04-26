from pydantic import BaseModel, Field


class AnalyzerInput(BaseModel):
    file_path: str = Field(description="Absolute path to the .py file")
    code: str = Field(description="Complete content of the .py file")
