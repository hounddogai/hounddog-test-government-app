# Example Government Application in C#

An example government web application written in C#/.NET with embedded sensitive data security flaws. This fictitious 
classified documents portal allows government contractors to access classified documents based on their clearance level.

## Tech Stack
- C# and ASP.NET Core 6.0
- Blazor Server with MudBlazor components
- Entity Framework Core 6.0.24 with SQLite database
- MediatR

## Basic Functionality
- Users are able to Login and Register with all necessary data (using Microsoft Identity)
- Users are able to view a list of documents in a table according to their security clearance level.
- Users are able to view General information such as username, name, email address, physical address and profile picture
  that can be edited.
- Users are able to view Security clearance information such as background check status, security clearance granted,
  Department of Defense Contractor Number and US Federal Contractor Registration Number.
- Users are able to update their password in Account security settings tab.
- On each login, the application creates a log in a textual file that exposes sensitive information such as Name, Email,
  Security clearance, Background check status, Department of Defense Contractor Number and US Federal Contractor
  Registration Number. The log is saved in a textual file named Logs-.txt.

| Security Clearance | Documents                           |
|--------------------|-------------------------------------|
| Top Secret         | Confidential, Secret and Top Secret |
| Secret             | Confidential and Secret             |
| Confidential       | Confidential                        |

## Default Accounts

| Username      | Password      |
|---------------|---------------|
| matthewparker | matthewparker |
| johndoe       | johndoe       |
| janedoe       | janedoe       |

## Setup Instructions
1. cd to Dockerfile that is located in the root folder of the ClassifiedDocumentPortal solution
2. docker build -t classified-document-portal .
3. docker run -p 8080:80 classified-document-portal
4. navigate to http://localhost:8080/
