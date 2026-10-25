# Team Members and Contributions

The Honeypot-Based Cyberattack Intelligence Platform was developed collaboratively by the following members, who contributed across implementation, testing, integration, documentation, and validation. This document summarizes each member's primary areas of contribution, including work that may not be fully represented by GitHub commit history.

## 1. Elselam Berhanu — CTC-5653-26

**Primary areas: Pipeline Development, Integration, and Coordination**

- Contributed to the main processing pipeline connecting event collection, normalization, storage, and analysis.
- Coordinated integration across the project's modules and helped resolve compatibility issues between components.
- Configured a shared-folder connection between the Cowrie honeypot environment and the project system to transfer Cowrie logs for processing and analysis.
- Conducted end-to-end pipeline testing using Cowrie log data.

## 2. Hawinet Teshome — CTC-977-26

**Primary areas: Event Collection, Normalization, and Cowrie Testing**

- Contributed to the event collector and the normalization of Cowrie JSON log records into the platform's standardized event format.
- Prepared and examined sample events to help validate the processing of incoming honeypot data.
- Contributed to Cowrie setup and testing, including verifying that generated log events could be collected and processed by the platform.
- Helped validate the consistency and usability of collected event data.

## 3. Firaol Tadesse — CTC-1192-26

**Primary areas: Updated Dashboard, Frontend Design, and Dashboard Testing**

- Developed an updated version of the Streamlit dashboard, improving the presentation of collected events, summary metrics, and security alerts.
- Contributed to the dashboard's frontend design and visual layout to improve usability and the presentation of security information.
- Tested the updated dashboard locally before pushing it to the repository, collaborating with Yadeno Demissie on testing and integration.
- Helped validate the dashboard's functionality and presentation for the final system demonstration.

## 4. Kidus Elias — CTC-709-26

**Primary areas: Security Event Analysis and Analysis Testing**

- Contributed to the analysis module for interpreting normalized honeypot events.
- Worked on identifying suspicious activity patterns and generating useful event summaries and alerts.
- Tested analysis behavior using representative events and different test scenarios.
- Helped validate the consistency of analysis results and the handling of different event types.

## 5. Yadeno Demissie — CTC-5884-26

**Primary areas: Dashboard Components, Setup Documentation, and Testing Results**

- Contributed to the Streamlit dashboard.
- Prepared and updated documentation covering project setup, execution instructions, and testing results so users and evaluators can understand how to run and validate the platform.
- Collaborated on dashboard testing and validation before the updated dashboard was pushed to the repository.

## 6. Yohannes Belay — CTC-1445-26

**Primary areas: Data Storage and Database Testing**

- Contributed to the storage module and the persistence of normalized events in the SQLite database.
- Worked on database initialization, event insertion, and retrieval workflows.
- Tested database behavior and helped validate that stored events could be retrieved for analysis and dashboard display.
- Contributed to checking data consistency and the interaction between storage and other system components.
