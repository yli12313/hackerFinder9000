# Detecting Piecewise Cyber Espionage in Model APIs

<img width="1404" height="534" alt="image" src="https://github.com/user-attachments/assets/88f386a4-0fb3-4438-ab29-849abd190755" />


**Project Description**: On November 13th 2025, Anthropic published a report on an AI-orchestrated cyber espionage campaign. Threat actors used various techniques to circumvent model safeguards and used Claude Code with agentic scaffolding to automate large parts of their campaigns. Specifically, threat actors split campaigns into subtasks that in isolation appeared benign. It is therefore important to find methods to protect against such attacks to ensure that misuse of AI in the cyber domain can be minimized. To address this, we propose a novel method for detecting malicious activity in model APIs across piecewise benign requests. We simulated malicious campaigns using an agentic red-team scaffold similar to what was described in the reported attack. We demonstrate that individual attacks are blocked by simple guardrails using Llama Guard 3. Then, we demonstrate that by splitting up the attack, this bypasses the guardrail. For the attacks that get through, a classifier model is introduced that detects those attacks, and a statistical validation of the detections is provided. This result paves the way to detect future automated attacks of this kind.

