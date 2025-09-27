import json
import re
from crewai import Crew, Process
from textwrap import dedent
from agents import SecurityAgents
from security_tasks import SecurityTasks
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
import os
from dotenv import load_dotenv
load_dotenv()

groq = ChatGroq(api_key=os.environ.get("GROQ_API_KEY"))
# gemini = ChatGoogleGenerativeAI(model="gemini-pro",google_api_key="insert your google api key here")
# openai = ChatOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
class SecurityCrew:

  def __init__(self, code_snippet):
    self.code_snippet = code_snippet

  def run(self):
    agents = SecurityAgents()
    tasks = SecurityTasks()

    code_review_agent = agents.code_review_agent()
    vulnerability_write_up = agents.vulnerability_write_up()
    exploit_vulnerability = agents.exploit_vulnerability()
    suggest_mitigation = agents.suggest_mitigation()
    security_manager = agents.security_manager()

    review_code_task = tasks.review_code(
      code_review_agent, self.code_snippet
    )

    
    exploit_vulnerability_task = tasks.vulnerability_exploit(
      exploit_vulnerability, context=[review_code_task], 
      code=self.code_snippet
      )
    
    suggest_mitigation_task = tasks.mitigation_strategy(
      suggest_mitigation, context=[review_code_task, exploit_vulnerability_task],
      code=self.code_snippet
    )

    vulnerability_writeup = tasks.vulnerability_writeup(
      vulnerability_write_up, context = [review_code_task,exploit_vulnerability_task, suggest_mitigation_task], code=self.code_snippet
      )
    security_manager_task = tasks.security_assessment(
      security_manager, context=[review_code_task, vulnerability_writeup, exploit_vulnerability_task, suggest_mitigation_task],
      code=self.code_snippet
    )

    crew = Crew(
      agents=[
        code_review_agent, vulnerability_write_up, exploit_vulnerability, suggest_mitigation, security_manager
      ],
      tasks=[review_code_task, exploit_vulnerability_task, suggest_mitigation_task, vulnerability_writeup],
      verbose=True,
      process=Process.hierarchical,
      manager_llm=groq
    )

    result = crew.kickoff()
    print(result)
    
    return result

if __name__ == "__main__":
  print("## Welcome to Security Review")
  print('-------------------------------')
  with open('test_example.py', 'r') as file:
    code_snippet = file.read()
  
  # print(code_snippet)
  security_crew = SecurityCrew(code_snippet = code_snippet)
  result = security_crew.run()
  print("\n\n########################")
  print("## Here is your Security Review")
  print("########################\n")
  print(result)
