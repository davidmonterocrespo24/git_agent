# GitHub Code Analyzer

This project is an automated tool that analyzes Python code in a Git repository, identifies issues related to logic, performance, best practices, and security, and creates issues or pull requests on GitHub for each problem found. The tool uses the GitHub API and an AI model to carry out its analysis.

## Features

- **Code Analysis:** Detects errors, performance improvements, readability enhancements, and security vulnerabilities.
- **Issue and Pull Request Creation:** Automatically generates GitHub issues detailing each problem found and creates pull requests for critical issues.
- **Issue Summary:** Consolidates detected issues into a global summary report.
- **AI Automation:** Utilizes the OpenAI API to provide automated suggestions.

## Prerequisites

- Python 3.8 or higher
- Access to a Git repository to work with
- Clone the target repository locally

## Installation

1. **Clone the Repository**

   Clone this project to your local machine:
   ```bash
   git clone [REPO_URL]
   cd [DIRECTORY_NAME]
   ```

2. **Install Dependencies**

   Use `pip` to install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**

   Create a `.env` file in the project directory with the following content:

   ```plaintext
   GITHUB_TOKEN=your_github_token
   GITHUB_REPO_OWNER=repository_owner_name
   GITHUB_REPO_NAME=repository_name
   OPENAI_API_KEY=your_openai_api_key
   MODEL_NAME=model_name
   ```

   Ensure you replace the placeholder values with your actual configuration keys and names.

## Usage

Run the main script to start analyzing:

```bash
python github_issue.py
```

Follow the console instructions to provide the path to the repository and the folder you wish to analyze.

## Contributing

If you want to contribute to this project, here are the standard steps for open-source contributions:

1. Fork the repository.
2. Create a new branch for your changes (`git checkout -b feature/newfeature`).
3. Make your modifications.
4. Commit your changes (`git commit -m 'Add new feature'`).
5. Push your changes to the branch (`git push origin feature/newfeature`).
6. Open a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.
