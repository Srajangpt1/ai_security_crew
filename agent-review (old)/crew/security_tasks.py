from crewai import Task
from textwrap import dedent


class SecurityTasks:
    def __tip_section(self):
        return "If you do your BEST WORK, I'll give you a $10,000 commission!"

    def review_code(self, agent, code):
        return Task(
            description=dedent(
                f"""
                **Task**: Review the code for security vulnerabilities
                **Description**: Given a code snippet, review it for security vulnerabilities. 
                Look for all possible vulnerabilities and security issues, do not miss anything. 
                **Parameters**:
                - code: {code}
                
                **Notes**: {self.__tip_section()}
                """
            ),
            agent=agent,
            async_execution=True
        )
    
    def vulnerability_writeup(self, agent, context, code):
        return Task(
            description=dedent(
                f"""
                **Task**: Write a detailed vulnerability report for the vulnerabilities identified in the code
                **Description**: Given a list of vulnerabilities in the code snippet, write a detailed write up about the vulnerabilities and how they are identified in the code. 
                It should be simple enough to be understood by a non-technical person while also providing detailed technical information.
                Write about the impact and potential risks associated with each vulnerability.
                your report should be in markdown format.
                **Parameters**:
                - code: {code}
                
                **Notes**: {self.__tip_section()}
                """
            ),
            agent=agent,
            async_execution=False,
            context=context
        )
    
    def vulnerability_exploit(self, agent, context, code):
        return Task(
            description=dedent(
                f"""
                **Task**: Exploit the vulnerabilities identified in the code
                **Description**: Given the code and list of vulnerabilities in the code, exploit the vulnerabilities to demonstrate the impact and potential risks associated with each vulnerability. 
                Identify the steps taken to exploit the vulnerabilities and the results obtained.
                Give the successful payload of the vulnerability.
                You can provide the full curl command or any other tool used to exploit the vulnerability.
                Link the vulnerabilities and steps that are required to exploit them. 
                Provide a detailed explanation of the exploitation process and the results obtained.
                **Parameters**:
                - code: {code}
                
                **Notes**: {self.__tip_section()}
                """
            ),
            agent=agent,
            async_execution=False,
            context=context
        )
    
    def mitigation_strategy(self, agent, context, code):
        return Task(
            description=dedent(
                f"""
                **Task**: Develop a mitigation startegy for the identified vulnerabilities in the code
                **Description**: Given the code, list of vulnerabilities in the code and the successful exploits of those vulnerabilities, develop a mitigation strategy to address and fix the vulnerabilities. 
                Provide detailed steps on how to fix each vulnerability. You should suggest exact code changes or security configurations to mitigate the vulnerabilities.
                Your mitigation strategy should be practical and effective in addressing the identified vulnerabilities.
                **Parameters**:
                - code: {code}
                
                **Notes**: {self.__tip_section()}
                """
            ),
            agent=agent,
            async_execution=False,
            context=context
        )
    
    def security_assessment(self, agent, context, code):
        return Task(
            description=dedent(
                f"""
                **Task**: Perform a security assessment on the code
                **Description**: Given a code snippet, perform a comprehensive security assessment to identify vulnerabilities. 
                Start by reviewing the code for security vulnerabilities, 
                next, identify the exploits for those vulnerabilities
                then suggest the mitigations that are required to fix those vulnerabilities.
                and finally, write a detailed report on the security assessment findings.
                
                Provide a detailed report on the security assessment findings, including the vulnerabilities identified, their successful exploit details and their mitigation strategy.
                **Parameters**:
                - code: {code}
                
                **Notes**: {self.__tip_section()}
                """
            ),
            agent=agent,
            context=context,
            async_execution=True
        )
    