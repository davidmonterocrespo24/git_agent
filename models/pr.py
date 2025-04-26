from pydantic import BaseModel, Field


class PRPayload(BaseModel):
    title: str = Field(...)
    body: str = Field(...)
    head_branch: str = Field(..., description="Branch containing the changes")
    base_branch: str = Field(default="main")
