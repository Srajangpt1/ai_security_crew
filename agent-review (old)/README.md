# AI Security Crew

This project aims to build a team of AI agents that can perform a comprehensive code review. The AI agents are designed to identify potential security vulnerabilities, write exploits, work on mitigations, and generate a detailed report of their findings.

## Installation

To install the dependencies for the AI agents, use the following command:

`poetry install --no-root`

## Running the main file
`poetry run python main.py`


## Adding API keys to .env file
1. Create a new file named `.env` in the root directory of your project.
2. Open the `.env` file and add the API keys in the following format:
    ```
    OPENAI_API_KEY = 'OPENAI_API_KEY'
    OPENAI_ORGANIZATION_ID = 'OPENAI_ORGANIZATION_ID'
    GROQ_API_KEY='GROQ_API_KEY'
    ```
    Replace your keys with the actual API keys.
3. Save the `.env` file.
