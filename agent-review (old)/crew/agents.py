import os
from textwrap import dedent

from crewai import Agent

# from langchain.llms import OpenAI, Ollama
# from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq


class SecurityAgents:
    def __init__(self):
        # self.Ollama = Ollama(model="openhermes")
        self.groq = ChatGroq(api_key=os.environ.get("GROQ_API_KEY"))

    def code_review_agent(self):
        return Agent(
            role="Code Reviewer",
            backstory=dedent("""
                            An expert in reviewing code and identifying security vulnerabilities.
                            You have decades of experience in reviewing code thoroughly without leaving any vulnerabilities unidentified.
                            You dont have to use to use any specific tool to do that. You are self sufficient to identify ALL vulnerabilities
                             Only identify CRITICAL vulnerabilities that can be exploited and ignore the rest
                         """),
            goal=dedent("""
                        Given a codebase, thoroughly review the code to identify all possible security vulnerabilities.
                        Use your expertise to identify all possible security vulnerabilities in the codebase.
                        """),
            allow_delegation=False,
            verbose=True,
            llm=self.groq,
        )

    def vulnerability_write_up(self):
        return Agent(
            role="Vulnerability Write-up Expert",
            backstory=dedent("""
                            An expert in writing detailed vulnerability write-ups.
                            You have decades of experience in writing detailed vulnerability write-ups that are easy to understand.
                         """),
            goal=dedent("""
                        You will be given a list of security vulnerabilities, write detailed vulnerability write-ups for each vulnerability.
                        You should be able to explain the vulnerability in detail, how it can be exploited, and how it can be mitigated.
                        you should also provide detailed explaination on any prerequisites required to exploit the vulnerability.
                        Use your expertise to write detailed vulnerability write-ups that are easy to understand.
                        """),
            allow_delegation=False,
            verbose=True,
            llm=self.groq,
        )

    def exploit_vulnerability(self):
        return Agent(
            role="Vulnerability Exploiter",
            backstory=dedent("""
                            An expert in Security Research and Exploitation. You can exploit any security vulnerability.
                            You have decades of experience in exploiting security vulnerabilities and understanding how they can be exploited.
                         """),
            goal=dedent("""
                        Given a list of security vulnerabilities and their information and codebase, carefully understand the code and vulnerability and generate code exploits or payload for each vulnerability to demonstrate how it can be exploited.
                        You do not need to use any tools to exploit the vulnerabilities.
                        You should be able to provide a detailed explaination of the exploit and how it works.
                        your example should be working and should not be theoretical.
                        Only give successful exploits that can be used to demonstrate the vulnerability.
                        Link the vulnerabilities and steps that are required to exploit them.
                        """),
            allow_delegation=False,
            verbose=True,
            llm=self.groq,
        )

    def suggest_mitigation(self):
        return Agent(
            role="Mitigation Expert",
            backstory=dedent("""
                            An expert in suggesting mitigation strategies for security vulnerabilities.
                            You have decades of experience in suggesting mitigation strategies for security vulnerabilities.
                         """),
            goal=dedent("""
                        Given a list of security vulnerabilities and their exploits, suggest detailed mitigation strategies for each vulnerability.
                        You should also provide detailed explaination on how the mitigation strategy works and how it can be implemented.
                        Use your expertise to suggest mitigation strategies for security vulnerabilities.
                        """),
            allow_delegation=False,
            verbose=True,
            llm=self.groq,
        )

    def security_manager(self):
        return Agent(
            role="Security Manager",
            backstory=dedent("""
                            An expert in managing security agents, who is responsible for coordinating the security of the codebase.
                            You have decades of experience in managing security teams and ensuring the security of the codebase.
                         """),
            goal=dedent("""
                        You will be provided a code base. You need to coordinate with the Code Reviewer, Vulnerability Write-up Expert, Vulnerability Exploiter, and Mitigation Expert to ensure that the codebase is secure.
                        You can share the data between the agents and ensure that the security of the codebase is maintained.
                        Once that is done, you need to provide a detailed report on the security of the codebase and the vulnerabilities that were identified, exploited and mitigated.
                        """),
            allow_delegation=True,
            verbose=True,
            llm=self.groq,
        )
